//! The ring page the network driver and `netd` share, and the packet buffers next to it.
//!
//! Four single-producer single-consumer rings of 64 entries, each a producer index and a consumer index (free-running
//! `u32`s, in separate cache lines) followed by the entries:
//!
//! | ring | producer | consumer | entry |
//! |---|---|---|---|
//! | RXQ | driver | netd | receive slot \| frame length (with the 12-byte virtio header) << 16 |
//! | RXFREE | netd | driver | receive slot, finished with: the driver gives it back to the device |
//! | TXQ | netd | driver | transmit slot \| frame length << 16 (the frame starts 12 bytes into the slot) |
//! | TXDONE | driver | netd | transmit slot, the device has sent it |
//!
//! Slots are 2 KiB pieces of the shared buffer area: 64 receive slots first, then 32 transmit slots. Words after the
//! rings: the device's MAC address, a "driver is up" word and an epoch that changes whenever the driver (re)starts.
#![no_std]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

pub const SLOT: usize = 2048;
pub const NRX: usize = 64;
pub const NTX: usize = 32;
pub const HDR: usize = 12;
pub const RING_ENTRIES: usize = 64;

pub const RXQ: usize = 0x000;
pub const RXFREE: usize = 0x200;
pub const TXQ: usize = 0x400;
pub const TXDONE: usize = 0x600;
/// MAC address (6 bytes), then `READY` (u32), `EPOCH` (u32).
pub const INFO: usize = 0x800;
pub const READY: usize = INFO + 8;
pub const EPOCH: usize = INFO + 12;
/// How many ticks the driver may sleep before it must wake `netd` again (written by `netd` from its next timer: an idle
/// network lets the whole machine sleep).
pub const POLL: usize = INFO + 16;

/// One end of a ring at `base` (the ring page's address in this task plus the ring's offset).
///
/// The type's invariant: `base` is the address of a mapped, 4-aligned region of at least `RING_BYTES` bytes in this task for
/// as long as the `Ring` is used (so its methods can be safe). `Ring::at` is how one is made.
#[derive(Clone, Copy)]
pub struct Ring(usize);

/// Bytes a ring occupies: producer word, consumer word (one cache line each) and the entries.
pub const RING_BYTES: usize = 128 + 4 * RING_ENTRIES;

impl Ring {
    /// # Safety
    /// `base .. base + RING_BYTES` must be mapped read-write in this task, 4-aligned, and stay mapped while the `Ring` (or a
    /// copy) is used.
    pub unsafe fn at(base: usize) -> Ring {
        Ring(base)
    }

    fn prod(&self) -> *mut u32 {
        self.0 as *mut u32
    }
    fn cons(&self) -> *mut u32 {
        (self.0 + 64) as *mut u32
    }
    fn entry(&self, i: u32) -> *mut u32 {
        (self.0 + 128 + 4 * (i as usize % RING_ENTRIES)) as *mut u32
    }

    pub fn len(&self) -> u32 {
        fence(Ordering::SeqCst);
        // SAFETY: `Ring::at`'s contract: the ring region is mapped and aligned, so the producer and consumer words are valid to read.
        unsafe { read_volatile(self.prod()).wrapping_sub(read_volatile(self.cons())).min(RING_ENTRIES as u32) }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_full(&self) -> bool {
        self.len() as usize >= RING_ENTRIES
    }

    /// Producer: add an entry (false if full).
    pub fn push(&self, v: u32) -> bool {
        if self.is_full() {
            return false;
        }
        // SAFETY: prod/cons/entry all lie inside the ring page `Ring` was built on (see `len`); entry index is reduced modulo RING_ENTRIES; volatile because the peer task writes the same shared memory.
        unsafe {
            let p = read_volatile(self.prod());
            write_volatile(self.entry(p), v);
            fence(Ordering::SeqCst);
            write_volatile(self.prod(), p.wrapping_add(1));
        }
        true
    }

    /// Consumer: take the oldest entry.
    pub fn pop(&self) -> Option<u32> {
        if self.is_empty() {
            return None;
        }
        // the entry must not be read before the producer's index is seen (a control dependency does not order two loads on Arm)
        fence(Ordering::Acquire);
        // SAFETY: as in `push`: the consumer index and the entry (index taken modulo RING_ENTRIES, so never outside the ring) are in the shared page; volatile because the peer writes them.
        unsafe {
            let c = read_volatile(self.cons());
            let v = read_volatile(self.entry(c));
            fence(Ordering::SeqCst);
            write_volatile(self.cons(), c.wrapping_add(1));
            Some(v)
        }
    }

    /// Forget everything (the producer's side restarting).
    pub fn reset(&self) {
        // SAFETY: same ring page as above; reset is called only by the side that owns the restart, before the peer relies on the indices.
        unsafe {
            write_volatile(self.prod(), 0);
            write_volatile(self.cons(), 0);
        }
    }
}

pub fn entry(slot: usize, len: usize) -> u32 {
    slot as u32 | (len as u32) << 16
}

pub fn unpack(v: u32) -> (usize, usize) {
    ((v & 0xFFFF) as usize, (v >> 16) as usize)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    use std::sync::Arc;
    use std::vec;

    fn page() -> std::boxed::Box<[u64; 512]> {
        std::boxed::Box::new([0u64; 512])
    }

    #[test]
    fn entries_come_out_in_order_across_wraparound() {
        let mem = page();
        let r = Ring(mem.as_ptr() as usize);
        for round in 0..5u32 {
            for i in 0..RING_ENTRIES as u32 {
                assert!(r.push(round * 1000 + i));
            }
            assert!(r.is_full() && !r.push(7), "a full ring refuses");
            for i in 0..RING_ENTRIES as u32 {
                assert_eq!(r.pop(), Some(round * 1000 + i));
            }
            assert_eq!(r.pop(), None);
        }
    }

    #[test]
    fn a_hostile_producer_index_cannot_make_the_consumer_read_outside_the_ring() {
        let mem = page();
        let r = Ring(mem.as_ptr() as usize);
        // SAFETY: test only: `mem` is a live, 8-aligned 4 KiB boxed array and `prod()` is its first word.
        unsafe { write_volatile(r.prod(), u32::MAX) }; // the peer claims four billion entries
        assert_eq!(r.len() as usize, RING_ENTRIES);
        let mut n = 0;
        while r.pop().is_some() && n < 10 * RING_ENTRIES {
            n += 1;
        }
        assert!(n >= RING_ENTRIES); // (it keeps handing out ring slots, never an address outside the page)
    }

    #[test]
    fn one_producer_and_one_consumer_never_lose_or_reorder_entries() {
        let mem: Arc<[u64; 512]> = Arc::new([0u64; 512]);
        let base = mem.as_ptr() as usize;
        let stop = Arc::new(AtomicBool::new(false));
        let total = 200_000u32;
        let prod = std::thread::spawn(move || {
            let r = Ring(base);
            let mut i = 0u32;
            while i < total {
                if r.push(i) {
                    i += 1;
                }
            }
        });
        let seen = Arc::clone(&mem);
        let s2 = stop.clone();
        let cons = std::thread::spawn(move || {
            let r = Ring(seen.as_ptr() as usize);
            let mut expect = 0u32;
            let mut out = vec![];
            while expect < total && !s2.load(SeqCst) {
                if let Some(v) = r.pop() {
                    if v != expect {
                        out.push((expect, v));
                        expect = v;
                    }
                    expect += 1;
                }
            }
            out
        });
        prod.join().unwrap();
        let bad = cons.join().unwrap();
        stop.store(true, SeqCst);
        assert!(bad.is_empty(), "entries lost or out of order: {:?}", &bad[..bad.len().min(5)]);
    }
}

/// The message word the network driver sends `netd` when there is news (the driver is role 18, `netd` role 19).
pub const NET_EVENT: u64 = 0x100;
