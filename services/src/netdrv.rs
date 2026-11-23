//! The network driver (role 18): virtio-net over PCI. It moves frames between the device's two queues and the rings
//! `netd` shares with it (see `netring`), and nothing else: it neither parses a frame nor keeps any state about
//! connections, so a crash costs only the frames in flight, and the kernel restarts it.
//!
//! One loop: wait for the device's interrupt, a kick from `netd` (`IRQ_RAISE`) or one tick; then hand received frames
//! to `netd`, give finished receive slots back to the device, report sent frames, and queue the frames `netd` wants
//! sent. `netd` is told (a message to its endpoint) whenever there is something for it, and once per tick.
use metallium_net_ring::*;
use metallium_driver_rt::virtio;
use metallium_driver_rt::*;

const MMIO_VA: usize = 0x8020_0000;
const QUEUES_VA: usize = 0x8021_0000;
const CFG_VA: usize = 0x8023_0000;
const RING_VA: usize = 0x8024_0000;
const BUFS_VA: usize = 0x8030_0000;

/// virtio-net feature bit 5: the device has a MAC address (in its configuration).
const F_MAC: u32 = 1 << 5;

struct Dev {
    rx: virtio::Queue,
    tx: virtio::Queue,
    bufs_pa: u64,
    pci: virtio::Pci,
}

fn rx_buf(bufs_pa: u64, slot: usize) -> virtio::Buf {
    virtio::Buf { pa: bufs_pa + (slot * SLOT) as u64, va: va(BUFS_VA) + slot * SLOT, len: SLOT as u32, dev_writes: true }
}

fn init() -> Result<Dev, &'static str> {
    if mem_map(1, MMIO_VA, true) != 0 || mem_map(2, QUEUES_VA, true) != 0 || mem_map(3, CFG_VA, false) != 0 || mem_map(5, RING_VA, true) != 0 {
        return Err("mapping failed");
    }
    if mem_map(4, BUFS_VA, true) != 0 {
        return Err("mapping the buffers failed");
    }
    let (s1, _, bar_pages, _) = cap_info(1);
    let (s2, queues_pa, _, _) = cap_info(2);
    let (s4, bufs_pa, _, _) = cap_info(4);
    if s1 != 0 || s2 != 0 || s4 != 0 {
        return Err("cap_info failed");
    }
    // SAFETY: the BAR and config-space mappings the kernel gave this driver (`bar_pages` pages at MMIO_VA / CFG_VA, per its facts).
    let pci = unsafe { virtio::Pci::open(va(MMIO_VA), bar_pages as usize * 4096, va(CFG_VA), 0x1041) }?;
    pci.start_with(F_MAC)?;
    // SAFETY: QUEUES_VA is the two-page queue area mapped (checked) from capability 2 just above; the device has not been given the queues yet.
    unsafe { core::ptr::write_bytes(va(QUEUES_VA) as *mut u8, 0, 8192) }; // forget a crashed predecessor's ring state
    let rx = pci.queue_sized(0, NRX as u16, va(QUEUES_VA), queues_pa)?;
    let tx = pci.queue_sized(1, NTX as u16, va(QUEUES_VA) + 4096, queues_pa + 4096)?;
    pci.driver_ok();
    // tell netd who we are and start the shared rings afresh
    let mac_lo = pci.config32(0);
    let mac_hi = pci.config32(4);
    let ring = va(RING_VA);
    for r in [RXQ, RXFREE, TXQ, TXDONE] {
        // SAFETY: the ring page is mapped at RING_VA; `r` is one of its ring offsets.
        unsafe { Ring::at(ring + r) }.reset();
    }
    // SAFETY: RING_VA is the ring page mapped (checked) from capability 5; INFO..POLL are inside its first 0x820 bytes; netd waits for READY, which is written last, behind the fence.
    unsafe {
        let m = (ring + INFO) as *mut u8;
        for i in 0..4 {
            core::ptr::write_volatile(m.add(i), (mac_lo >> (8 * i)) as u8);
        }
        for i in 0..2 {
            core::ptr::write_volatile(m.add(4 + i), (mac_hi >> (8 * i)) as u8);
        }
        let epoch = core::ptr::read_volatile((ring + EPOCH) as *const u32);
        core::ptr::write_volatile((ring + EPOCH) as *mut u32, epoch.wrapping_add(1));
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile((ring + READY) as *mut u32, 1);
    }
    let mut d = Dev { rx, tx, bufs_pa, pci };
    for slot in 0..NRX {
        d.rx.post(slot as u16, rx_buf(bufs_pa, slot));
    }
    d.rx.kick();
    Ok(d)
}

pub fn net_driver() -> ! {
    println!("[net] driver starting");
    let mut d = match init() {
        Ok(d) => d,
        Err(e) => {
            println!("[net] init failed: {e}");
            exit(1)
        }
    };
    // SAFETY: the ring page is mapped and the MAC bytes at INFO..INFO+6 were written by this task in `init`; netd only reads them.
    let mac = unsafe { core::slice::from_raw_parts((va(RING_VA) + INFO) as *const u8, 6) };
    println!("[net] virtio-net ready, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, {NRX} receive and {NTX} transmit buffers", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    // SAFETY: the ring page is mapped at RING_VA; each offset is one of its rings.
    let (rxq, rxfree, txq, txdone) = unsafe { (Ring::at(va(RING_VA) + RXQ), Ring::at(va(RING_VA) + RXFREE), Ring::at(va(RING_VA) + TXQ), Ring::at(va(RING_VA) + TXDONE)) };
    let mut last_event = 0u64;
    loop {
        // an interrupt, a kick from netd, or a tick
        // SAFETY: the ring page is mapped; POLL is inside it; volatile because netd writes it.
        let poll = unsafe { core::ptr::read_volatile((va(RING_VA) + POLL) as *const u32) }.clamp(1, 100) as u64;
        let r = irq_wait_timeout(6, poll);
        if r == 0 {
            d.pci.ack_isr();
        }
        let mut news = false;
        // frames the device received
        let mut posted = false;
        while let Some((id, len)) = d.rx.next_used() {
            let (id, len) = (id as usize, len as usize);
            if id < NRX && len > HDR && len <= SLOT && rxq.push(entry(id, len)) {
                news = true;
            } else if id < NRX {
                d.rx.post(id as u16, rx_buf(d.bufs_pa, id)); // nonsense, or netd is behind: give it straight back
                posted = true;
            }
        }
        // slots netd has finished with go back to the device
        while let Some(v) = rxfree.pop() {
            let (slot, _) = unpack(v);
            if slot < NRX {
                d.rx.post(slot as u16, rx_buf(d.bufs_pa, slot));
                posted = true;
            }
        }
        if posted {
            d.rx.kick();
        }
        // frames the device has sent
        while let Some((id, _)) = d.tx.next_used() {
            if (id as usize) < NTX && txdone.push(id as u32) {
                news = true;
            }
        }
        // frames netd wants sent
        let mut sent = false;
        while let Some(v) = txq.pop() {
            let (slot, len) = unpack(v);
            if slot >= NTX || len == 0 || len + HDR > SLOT {
                continue;
            }
            let off = (NRX + slot) * SLOT;
            // SAFETY: slot < NTX and len + HDR <= SLOT were checked, so HDR bytes at the start of transmit slot (NRX + slot) lie inside the mapped BUFS_VA area; the device is not using this slot (netd owns it until it is posted below).
            unsafe { core::ptr::write_bytes((va(BUFS_VA) + off) as *mut u8, 0, HDR) }; // the virtio header: no offloads
            d.tx.post(slot as u16, virtio::Buf { pa: d.bufs_pa + off as u64, va: va(BUFS_VA) + off, len: (len + HDR) as u32, dev_writes: false });
            sent = true;
        }
        if sent {
            d.tx.kick();
        }
        let now = ticks();
        if news || now != last_event {
            last_event = now;
            // a message to netd: frames are waiting for it, or a tick has passed (it needs the time for its timers)
            let _ = send(0, [NET_EVENT, rxq.len() as u64, 0]);
        }
    }
}
