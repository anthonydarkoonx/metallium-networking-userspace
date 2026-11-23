//! TCP, from RFC 9293 (the state machine and segment processing), RFC 5681 and 6582 (slow start, congestion avoidance,
//! fast retransmit and NewReno recovery), RFC 6298 (the retransmission timer), RFC 7323 (window scaling) and RFC 5961
//! (blind-reset protection). Not implemented: selective acknowledgements, timestamps, urgent data, keep-alive.
//!
//! A `Tcb` is one connection. It never touches the network itself: segments go in through `segment`, and `output`
//! hands back the segments it wants sent now (it is called after every input, every application call and every timer).
use crate::wire::*;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
pub fn le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}
pub fn gt(a: u32, b: u32) -> bool {
    lt(b, a)
}
pub fn ge(a: u32, b: u32) -> bool {
    le(b, a)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Refused,
    Reset,
    TimedOut,
}

pub const MSL_MS: u64 = 2_000; // (RFC 9293 says two minutes; a stack that restarts often does not want to wait that long)
const MIN_RTO: u64 = 200;
const MAX_RTO: u64 = 60_000;
const INITIAL_RTO: u64 = 1_000;
const MAX_DATA_RETRIES: u32 = 10;
const MAX_SYN_RETRIES: u32 = 6;
const DELAYED_ACK_MS: u64 = 40;
const MAX_OOO_BYTES: usize = 64 * 1024;

pub struct Config {
    pub send_buf: usize,
    pub recv_buf: usize,
    pub mss: u16,
}

impl Default for Config {
    fn default() -> Config {
        Config { send_buf: 64 * 1024, recv_buf: 64 * 1024, mss: 1460 }
    }
}

/// Bytes that arrived out of order, by distance from `rcv_nxt`.
#[derive(Default)]
struct Reassembly {
    data: VecDeque<u8>,
    have: VecDeque<bool>,
}

impl Reassembly {
    fn insert(&mut self, off: usize, bytes: &[u8]) {
        if self.data.len() < off + bytes.len() {
            self.data.resize(off + bytes.len(), 0);
            self.have.resize(off + bytes.len(), false);
        }
        for (i, &b) in bytes.iter().enumerate() {
            self.data[off + i] = b;
            self.have[off + i] = true;
        }
    }

    /// The offsets move up by `n` (that many bytes were taken in order).
    fn advance(&mut self, n: usize) {
        let n = n.min(self.data.len());
        self.data.drain(..n);
        self.have.drain(..n);
    }

    /// Take the bytes at the front that have all arrived.
    fn take_contiguous(&mut self) -> Vec<u8> {
        let n = self.have.iter().take_while(|&&h| h).count();
        let out: Vec<u8> = self.data.drain(..n).collect();
        self.have.drain(..n);
        out
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

pub struct Tcb {
    pub state: State,
    pub local: (Ip, u16),
    pub remote: (Ip, u16),
    pub error: Option<Error>,
    cfg: Config,

    // sending
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    /// The highest sequence number ever sent (after a timeout `snd_nxt` goes back, but the peer may still acknowledge up to here).
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    snd_scale: u8,
    mss: u32,
    /// Bytes from `sendq_seq` on: sent but not acknowledged, then not yet sent.
    sendq: VecDeque<u8>,
    sendq_seq: u32,
    fin_queued: bool,
    fin_sent: bool,
    nodelay: bool,

    // receiving
    irs: u32,
    rcv_nxt: u32,
    rcv_scale: u8,
    /// Right edge of the window we have offered so far.
    rcv_adv: u32,
    recvq: VecDeque<u8>,
    reasm: Reassembly,
    fin_received: bool,

    // congestion control
    cwnd: u32,
    ssthresh: u32,
    dupacks: u32,
    recover: u32,
    in_recovery: bool,
    /// Send one segment from `snd_una` at the next output (fast retransmit).
    retransmit_now: bool,

    // timers (milliseconds); None = off
    srtt: Option<u64>,
    rttvar: u64,
    rto: u64,
    rto_at: Option<u64>,
    retries: u32,
    rtt_probe: Option<(u32, u64)>,
    persist_at: Option<u64>,
    delack_at: Option<u64>,
    time_wait_at: Option<u64>,
    ack_now: bool,
    /// Segments' worth of data received since the last ACK went out.
    unacked_rx: u32,
    peer_sent_syn_opts: bool,
}

pub struct OutSeg {
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub payload: Vec<u8>,
}

fn scale_for(buf: usize) -> u8 {
    let mut s = 0;
    while s < 14 && (buf >> s) > 0xFFFF {
        s += 1;
    }
    s
}

impl Tcb {
    fn new(local: (Ip, u16), remote: (Ip, u16), iss: u32, cfg: Config, state: State) -> Tcb {
        let rcv_scale = scale_for(cfg.recv_buf);
        let mss = cfg.mss as u32;
        Tcb {
            state,
            local,
            remote,
            error: None,
            snd_una: iss,
            snd_nxt: iss,
            snd_max: iss,
            iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            snd_scale: 0,
            mss,
            sendq: VecDeque::new(),
            sendq_seq: iss.wrapping_add(1),
            fin_queued: false,
            fin_sent: false,
            nodelay: false,
            irs: 0,
            rcv_nxt: 0,
            rcv_scale,
            rcv_adv: 0,
            recvq: VecDeque::new(),
            reasm: Reassembly::default(),
            fin_received: false,
            cwnd: 10 * mss,
            ssthresh: u32::MAX,
            dupacks: 0,
            recover: iss,
            in_recovery: false,
            retransmit_now: false,
            srtt: None,
            rttvar: 0,
            rto: INITIAL_RTO,
            rto_at: None,
            retries: 0,
            rtt_probe: None,
            persist_at: None,
            delack_at: None,
            time_wait_at: None,
            ack_now: false,
            unacked_rx: 0,
            peer_sent_syn_opts: false,
            cfg,
        }
    }

    /// Active open: the SYN goes out with the next `output`.
    pub fn connect(local: (Ip, u16), remote: (Ip, u16), iss: u32, cfg: Config) -> Tcb {
        Tcb::new(local, remote, iss, cfg, State::SynSent)
    }

    /// Passive open: a SYN arrived for a listener.
    pub fn accept(local: (Ip, u16), remote: (Ip, u16), syn: &Tcp, iss: u32, cfg: Config) -> Tcb {
        let mut t = Tcb::new(local, remote, iss, cfg, State::SynReceived);
        t.irs = syn.seq;
        t.rcv_nxt = syn.seq.wrapping_add(1);
        t.take_syn_options(syn);
        t.snd_wnd = syn.window as u32; // (the window in a SYN is never scaled)
        t.snd_wl1 = syn.seq;
        t.snd_wl2 = iss;
        t
    }

    fn take_syn_options(&mut self, syn: &Tcp) {
        if let Some(m) = syn.options.mss {
            self.mss = (m as u32).clamp(64, self.cfg.mss as u32);
            self.cwnd = 10 * self.mss;
        }
        match syn.options.window_scale {
            Some(s) => {
                self.snd_scale = s;
                self.peer_sent_syn_opts = true;
            }
            None => {
                // the peer does not scale: neither do we
                self.snd_scale = 0;
                self.rcv_scale = 0;
            }
        }
    }

    /// A one-line summary of the connection's internals (for diagnostics and tests).
    pub fn summary(&self) -> alloc::string::String {
        alloc::format!(
            "{:?} una={} nxt={} flight={} wnd={} cwnd={} ssthresh={} recovery={} dup={} rto={} rto_at={:?} retries={} sendq={} recvq={} rcv_nxt={} ooo={} persist={:?} err={:?}",
            self.state,
            self.snd_una.wrapping_sub(self.iss),
            self.snd_nxt.wrapping_sub(self.iss),
            self.flight(),
            self.snd_wnd,
            self.cwnd,
            self.ssthresh,
            self.in_recovery,
            self.dupacks,
            self.rto,
            self.rto_at,
            self.retries,
            self.sendq.len(),
            self.recvq.len(),
            self.rcv_nxt.wrapping_sub(self.irs),
            self.reasm.data.len(),
            self.persist_at,
            self.error
        )
    }

    // ---- what the application sees ----------------------------------------------------------------------------------

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, State::Established | State::CloseWait | State::FinWait1 | State::FinWait2 | State::Closing | State::LastAck | State::TimeWait)
    }

    /// Room in the send buffer.
    pub fn send_space(&self) -> usize {
        if self.fin_queued || matches!(self.state, State::Closed | State::TimeWait | State::Closing | State::LastAck | State::FinWait1 | State::FinWait2) {
            return 0;
        }
        self.cfg.send_buf.saturating_sub(self.sendq.len())
    }

    /// Queue data for sending; how much was taken.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.send_space());
        self.sendq.extend(&data[..n]);
        n
    }

    /// Bytes ready to read.
    pub fn readable(&self) -> usize {
        self.recvq.len()
    }

    /// The peer has closed its side and everything it sent has been read.
    pub fn at_eof(&self) -> bool {
        self.fin_received && self.recvq.is_empty()
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.recvq.len());
        for (i, b) in self.recvq.drain(..n).enumerate() {
            buf[i] = b;
        }
        if n > 0 && self.window_to_offer() > self.offered_remaining() + (self.mss.min(self.cfg.recv_buf as u32 / 2)) {
            self.ack_now = true; // the window opened up enough to be worth telling the peer
        }
        n
    }

    /// Done sending: the FIN follows the queued data.
    pub fn close(&mut self) {
        match self.state {
            State::SynSent => self.state = State::Closed,
            State::Established | State::CloseWait | State::SynReceived => self.fin_queued = true,
            _ => {}
        }
    }

    /// Drop the connection: a RST goes out with the next `output` unless nothing was ever exchanged.
    pub fn abort(&mut self) -> Option<OutSeg> {
        let rst = match self.state {
            State::Closed | State::SynSent | State::TimeWait => None,
            _ => Some(OutSeg { flags: RST | ACK, seq: self.snd_max, ack: self.rcv_nxt, window: 0, mss: None, window_scale: None, payload: Vec::new() }),
        };
        self.state = State::Closed;
        self.error = Some(Error::Reset);
        rst
    }

    pub fn set_nodelay(&mut self, on: bool) {
        self.nodelay = on;
    }

    // ---- windows --------------------------------------------------------------------------------------------------------

    fn free_recv(&self) -> u32 {
        (self.cfg.recv_buf.saturating_sub(self.recvq.len())) as u32
    }

    /// The window we would offer now (receiver-side silly window avoidance: a window too small to matter is 0).
    fn window_to_offer(&self) -> u32 {
        let free = self.free_recv();
        if free >= self.mss.min(self.cfg.recv_buf as u32 / 2) {
            free
        } else {
            0
        }
    }

    /// What is left of the window already offered.
    fn offered_remaining(&self) -> u32 {
        let r = self.rcv_adv.wrapping_sub(self.rcv_nxt) as i32;
        r.max(0) as u32
    }

    /// The window field for the next segment (also moves the right edge we have offered).
    fn advertise(&mut self, syn: bool) -> u16 {
        let w = if syn {
            self.cfg.recv_buf.min(0xFFFF) as u32
        } else {
            // never take back what was offered: the peer may have sent into it already
            self.window_to_offer().max(self.offered_remaining()).min(self.free_recv().max(self.offered_remaining()))
        };
        let right = self.rcv_nxt.wrapping_add(w);
        if gt(right, self.rcv_adv) || syn {
            self.rcv_adv = right;
        }
        if syn {
            w as u16
        } else {
            (w >> self.rcv_scale).min(0xFFFF) as u16
        }
    }

    fn advance_nxt(&mut self, n: u32) {
        self.snd_nxt = self.snd_nxt.wrapping_add(n);
        if gt(self.snd_nxt, self.snd_max) {
            self.snd_max = self.snd_nxt;
        }
    }

    fn flight(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }

    // ---- input ----------------------------------------------------------------------------------------------------------

    fn set_error_closed(&mut self, e: Error) {
        self.error = Some(e);
        self.state = State::Closed;
        self.rto_at = None;
        self.persist_at = None;
        self.delack_at = None;
    }

    /// Process a segment for this connection. Returns segments to send at once (resets and challenge ACKs); the
    /// normal replies come from `output`.
    pub fn segment(&mut self, seg: &Tcp, now: u64) -> Option<OutSeg> {
        match self.state {
            State::Closed => return None,
            State::SynSent => return self.segment_syn_sent(seg, now),
            _ => {}
        }
        // 1. is the sequence number acceptable?
        let seg_len = seg.seq_len();
        let wnd = self.rcv_adv.wrapping_sub(self.rcv_nxt) as i32;
        let wnd = wnd.max(0) as u32;
        let wnd = wnd.max(self.window_to_offer());
        let acceptable = if seg_len == 0 {
            if wnd == 0 {
                seg.seq == self.rcv_nxt
            } else {
                ge(seg.seq, self.rcv_nxt) && lt(seg.seq, self.rcv_nxt.wrapping_add(wnd))
            }
        } else if wnd == 0 {
            false
        } else {
            let last = seg.seq.wrapping_add(seg_len - 1);
            (ge(seg.seq, self.rcv_nxt) && lt(seg.seq, self.rcv_nxt.wrapping_add(wnd))) || (ge(last, self.rcv_nxt) && lt(last, self.rcv_nxt.wrapping_add(wnd)))
        };
        if !acceptable {
            if seg.flags & RST == 0 {
                self.ack_now = true;
                if self.state == State::TimeWait {
                    self.time_wait_at = Some(now + 2 * MSL_MS);
                }
            }
            return None;
        }
        // 2. RST (RFC 5961: only an exact match resets; anything else in the window gets a challenge ACK)
        if seg.flags & RST != 0 {
            if seg.seq == self.rcv_nxt {
                let e = if self.state == State::SynReceived { Error::Refused } else { Error::Reset };
                if self.state == State::TimeWait {
                    self.state = State::Closed;
                } else {
                    self.set_error_closed(e);
                }
            } else {
                self.ack_now = true;
            }
            return None;
        }
        // 3. a SYN in the window is an error: challenge ACK
        if seg.flags & SYN != 0 {
            if self.state == State::SynReceived && seg.seq == self.irs {
                return None; // (a retransmitted SYN: the SYN|ACK goes out again below)
            }
            self.ack_now = true;
            return None;
        }
        if seg.flags & ACK == 0 {
            return None;
        }
        // 4. ACK processing
        if self.state == State::SynReceived {
            if le(self.snd_una, seg.ack) && le(seg.ack, self.snd_max) && gt(seg.ack, self.iss) {
                self.state = State::Established;
                self.snd_wnd = (seg.window as u32) << self.snd_scale;
                self.snd_wl1 = seg.seq;
                self.snd_wl2 = seg.ack;
            } else {
                return Some(OutSeg { flags: RST, seq: seg.ack, ack: 0, window: 0, mss: None, window_scale: None, payload: Vec::new() });
            }
        }
        if gt(seg.ack, self.snd_max) {
            self.ack_now = true; // acknowledges something we never sent
            return None;
        }
        self.process_ack(seg, now);
        if self.state == State::Closed {
            return None;
        }
        // 5. data and FIN
        self.process_text(seg, now);
        None
    }

    fn segment_syn_sent(&mut self, seg: &Tcp, now: u64) -> Option<OutSeg> {
        let ack_ok = seg.flags & ACK != 0 && gt(seg.ack, self.iss) && le(seg.ack, self.snd_max);
        if seg.flags & ACK != 0 && !ack_ok {
            if seg.flags & RST != 0 {
                return None;
            }
            return Some(OutSeg { flags: RST, seq: seg.ack, ack: 0, window: 0, mss: None, window_scale: None, payload: Vec::new() });
        }
        if seg.flags & RST != 0 {
            if ack_ok {
                self.set_error_closed(Error::Refused);
            }
            return None;
        }
        if seg.flags & SYN == 0 {
            return None;
        }
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.take_syn_options(seg);
        if ack_ok {
            self.snd_una = seg.ack;
            self.snd_wnd = seg.window as u32;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
            self.state = State::Established;
            self.rto_at = None;
            self.retries = 0;
            if let Some((s, t)) = self.rtt_probe.take() {
                if lt(s, seg.ack) {
                    self.rtt_sample(now.saturating_sub(t));
                }
            }
            self.ack_now = true;
        } else {
            // simultaneous open
            self.state = State::SynReceived;
            self.snd_wnd = seg.window as u32;
            self.snd_nxt = self.iss; // the SYN goes out again, now with an ACK
            self.snd_una = self.iss;
        }
        None
    }

    fn rtt_sample(&mut self, r: u64) {
        let r = r.max(1);
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(s) => {
                let err = if s > r { s - r } else { r - s };
                self.rttvar = (3 * self.rttvar + err) / 4;
                self.srtt = Some((7 * s + r) / 8);
            }
        }
        self.rto = (self.srtt.unwrap() + (4 * self.rttvar).max(10)).clamp(MIN_RTO, MAX_RTO);
    }

    fn process_ack(&mut self, seg: &Tcp, now: u64) {
        let ack = seg.ack;
        if lt(ack, self.snd_una) {
            return; // old
        }
        let advancing = gt(ack, self.snd_una);
        let window = (seg.window as u32) << self.snd_scale;
        let window_changed = window != self.snd_wnd;
        // window update (RFC 9293 3.10.7.4)
        if lt(self.snd_wl1, seg.seq) || (self.snd_wl1 == seg.seq && le(self.snd_wl2, ack)) {
            self.snd_wnd = window;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = ack;
        }
        if !advancing {
            // a duplicate ACK? (RFC 5681 §2)
            let outstanding = self.flight() > 0;
            if outstanding && seg.payload.is_empty() && seg.flags & (SYN | FIN) == 0 && !window_changed {
                self.dupacks += 1;
                if self.dupacks == 3 && !self.in_recovery_from_timeout_guard() {
                    // fast retransmit (RFC 5681 §3.2, NewReno RFC 6582)
                    self.ssthresh = (self.flight() / 2).max(2 * self.mss);
                    self.cwnd = self.ssthresh + 3 * self.mss;
                    self.recover = self.snd_nxt;
                    self.in_recovery = true;
                    self.retransmit_now = true;
                    self.rtt_probe = None;
                } else if self.dupacks > 3 && self.in_recovery {
                    self.cwnd += self.mss; // inflate: another segment left the network
                }
            }
            return;
        }
        // new data acknowledged
        let mut acked = ack.wrapping_sub(self.snd_una);
        let data_end = self.fin_seq();
        let fin_acked = self.fin_sent && ack == data_end.wrapping_add(1);
        self.snd_una = ack;
        if gt(ack, self.snd_nxt) {
            self.snd_nxt = ack; // (after a timeout we were resending from further back than the peer needed)
        }
        // the SYN takes one sequence number, the FIN another; what lies between is data
        let data_acked = if gt(ack, self.sendq_seq) { (ack.wrapping_sub(self.sendq_seq) as usize).min(self.sendq.len()) } else { 0 };
        self.sendq.drain(..data_acked);
        self.sendq_seq = self.sendq_seq.wrapping_add(data_acked as u32);
        if acked > 0 && self.retries > 0 {
            self.retries = 0;
        }
        // RTT measurement (Karn: only a segment sent once)
        if let Some((s, t)) = self.rtt_probe {
            if lt(s, ack) {
                self.rtt_sample(now.saturating_sub(t));
                self.rtt_probe = None;
            }
        }
        // congestion window
        if self.in_recovery {
            if ge(ack, self.recover) {
                self.cwnd = self.ssthresh.min(self.flight().max(self.mss) + self.mss);
                self.in_recovery = false;
                self.dupacks = 0;
            } else {
                // partial ACK: the next hole is lost too
                self.retransmit_now = true;
                self.cwnd = self.cwnd.saturating_sub(acked).saturating_add(self.mss);
                acked = 0;
            }
        } else {
            self.dupacks = 0;
            if self.cwnd < self.ssthresh {
                self.cwnd = self.cwnd.saturating_add(acked.min(self.mss));
            } else {
                self.cwnd = self.cwnd.saturating_add((self.mss * self.mss / self.cwnd.max(1)).max(1));
            }
        }
        let _ = acked;
        // timers
        if self.flight() == 0 {
            self.rto_at = None;
        } else {
            self.rto_at = Some(now + self.rto);
        }
        if self.snd_wnd > 0 {
            self.persist_at = None;
        }
        // our FIN acknowledged?
        if fin_acked {
            match self.state {
                State::FinWait1 => self.state = State::FinWait2,
                State::Closing => {
                    self.state = State::TimeWait;
                    self.time_wait_at = Some(now + 2 * MSL_MS);
                }
                State::LastAck => self.state = State::Closed,
                _ => {}
            }
        }
    }

    /// After a retransmission timeout the same lost segment must not trigger a fast retransmit for old duplicates.
    fn in_recovery_from_timeout_guard(&self) -> bool {
        self.in_recovery
    }

    fn fin_seq(&self) -> u32 {
        self.sendq_seq.wrapping_add(self.sendq.len() as u32)
    }

    fn process_text(&mut self, seg: &Tcp, now: u64) {
        let mut data = seg.payload;
        let mut seq = seg.seq;
        let mut fin = seg.flags & FIN != 0;
        // cut off what we have already received
        if lt(seq, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip >= data.len() {
                data = &[];
                if fin && skip > seg.payload.len() {
                    fin = false; // (the FIN was already taken too)
                }
            } else {
                data = &data[skip..];
            }
            seq = self.rcv_nxt;
        }
        let can_receive = matches!(self.state, State::Established | State::FinWait1 | State::FinWait2);
        if !can_receive {
            // CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT: the peer has finished; only a repeated FIN gets acknowledged
            if fin || !data.is_empty() {
                self.ack_now = true;
                if self.state == State::TimeWait {
                    self.time_wait_at = Some(now + 2 * MSL_MS);
                }
            }
            return;
        }
        // keep within the window we offered
        let room = self.rcv_adv.wrapping_sub(self.rcv_nxt) as i32;
        let room = (room.max(0) as u32).max(self.window_to_offer()) as usize;
        let offset = seq.wrapping_sub(self.rcv_nxt) as usize;
        let mut fits = data;
        if offset >= room {
            fits = &[];
        } else if offset + fits.len() > room {
            fits = &fits[..room - offset];
        }
        let truncated = fits.len() < data.len();
        if !fits.is_empty() {
            if offset == 0 {
                let free = self.cfg.recv_buf.saturating_sub(self.recvq.len());
                let take = fits.len().min(free);
                self.recvq.extend(&fits[..take]);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
                self.reasm.advance(take);
                let more = self.reasm.take_contiguous();
                if !more.is_empty() {
                    let free = self.cfg.recv_buf.saturating_sub(self.recvq.len());
                    let take = more.len().min(free);
                    self.recvq.extend(&more[..take]);
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
                    // (a contiguous run that did not fit is dropped: the peer will send it again)
                    self.reasm.advance(0);
                }
                self.unacked_rx += 1;
                if self.unacked_rx >= 2 || !self.reasm.is_empty() {
                    self.ack_now = true;
                } else if self.delack_at.is_none() {
                    self.delack_at = Some(now + DELAYED_ACK_MS);
                }
            } else if self.reasm.data.len() + fits.len() <= MAX_OOO_BYTES {
                self.reasm.insert(offset - 0, fits);
                self.ack_now = true; // a duplicate ACK tells the sender about the hole (RFC 5681 §3.2)
            } else {
                self.ack_now = true;
            }
        }
        // the FIN counts once everything before it has arrived
        if fin && !truncated && seq.wrapping_add(data.len() as u32) == self.rcv_nxt && !self.fin_received {
            self.fin_received = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.ack_now = true;
            match self.state {
                State::Established => self.state = State::CloseWait,
                State::FinWait1 => {
                    // our FIN was not acknowledged yet (or we would be in FinWait2)
                    self.state = State::Closing;
                }
                State::FinWait2 => {
                    self.state = State::TimeWait;
                    self.time_wait_at = Some(now + 2 * MSL_MS);
                }
                _ => {}
            }
        }
        // a FIN-WAIT-1 whose FIN was acknowledged by this very segment is already in FIN-WAIT-2 (process_ack)
    }

    // ---- timers ------------------------------------------------------------------------------------------------------------

    /// The time at which `poll` next needs to run.
    pub fn next_deadline(&self) -> Option<u64> {
        [self.rto_at, self.persist_at, self.delack_at, self.time_wait_at].into_iter().flatten().min()
    }

    fn on_timeout(&mut self, now: u64) {
        let limit = if matches!(self.state, State::SynSent | State::SynReceived) { MAX_SYN_RETRIES } else { MAX_DATA_RETRIES };
        self.retries += 1;
        if self.retries > limit {
            self.set_error_closed(Error::TimedOut);
            return;
        }
        // RFC 5681 §3.1 / RFC 6298 §5: back off, go back to the oldest unacknowledged data, one segment at a time
        self.rto = (self.rto * 2).min(MAX_RTO);
        self.rtt_probe = None;
        if matches!(self.state, State::SynSent | State::SynReceived) {
            self.snd_nxt = self.iss;
        } else {
            self.ssthresh = (self.flight() / 2).max(2 * self.mss);
            self.cwnd = self.mss;
            self.in_recovery = false;
            self.dupacks = 0;
            self.recover = self.snd_nxt;
            self.snd_nxt = self.snd_una;
        }
        self.rto_at = Some(now + self.rto);
    }

    // ---- output ----------------------------------------------------------------------------------------------------------------

    /// Everything this connection wants to send now.
    pub fn output(&mut self, now: u64) -> Vec<OutSeg> {
        let mut out = Vec::new();
        // timers
        if self.rto_at.is_some_and(|t| now >= t) && self.state != State::Closed {
            self.on_timeout(now);
        }
        if self.delack_at.is_some_and(|t| now >= t) {
            self.delack_at = None;
            self.ack_now = true;
        }
        if self.time_wait_at.is_some_and(|t| now >= t) {
            self.time_wait_at = None;
            self.state = State::Closed;
        }
        match self.state {
            State::Closed | State::TimeWait => {
                if self.state == State::TimeWait && self.ack_now {
                    out.push(self.seg(ACK, self.snd_max, Vec::new(), false));
                    self.ack_now = false;
                }
                return out;
            }
            State::SynSent => {
                if self.snd_nxt == self.iss {
                    self.advance_nxt(1);
                    let mut s = self.seg(SYN, self.iss, Vec::new(), true);
                    s.ack = 0;
                    self.rtt_probe = (self.retries == 0).then_some((self.iss, now));
                    self.rto_at.get_or_insert(now + self.rto);
                    out.push(s);
                }
                return out;
            }
            State::SynReceived => {
                if self.snd_nxt == self.iss {
                    self.advance_nxt(1);
                    let s = self.seg(SYN | ACK, self.iss, Vec::new(), true);
                    self.rtt_probe = (self.retries == 0).then_some((self.iss, now));
                    self.rto_at.get_or_insert(now + self.rto);
                    out.push(s);
                    self.ack_now = false;
                }
                return out;
            }
            _ => {}
        }
        // fast retransmit / NewReno partial ACK: one segment from the oldest unacknowledged byte
        if self.retransmit_now {
            self.retransmit_now = false;
            let len = self.sendq.len().min(self.mss as usize).min(self.flight() as usize);
            if len > 0 {
                let payload: Vec<u8> = self.sendq.iter().take(len).copied().collect();
                out.push(self.seg(ACK | PSH, self.snd_una, payload, false));
                self.rto_at = Some(now + self.rto);
                self.ack_now = false;
            }
        }
        // new data (and, when everything is out, the FIN)
        loop {
            let in_flight = self.flight();
            let sent_data = self.snd_nxt.wrapping_sub(self.sendq_seq) as usize; // bytes of sendq already sent (after a timeout: reset)
            let sent_data = if gt(self.snd_nxt, self.sendq_seq) { sent_data.min(self.sendq.len()) } else { 0 };
            let unsent = self.sendq.len() - sent_data;
            let wnd = self.snd_wnd.min(self.cwnd);
            let usable = wnd.saturating_sub(in_flight) as usize;
            if unsent > 0 && usable > 0 {
                let len = unsent.min(usable).min(self.mss as usize);
                // Nagle (RFC 9293 3.7.4): a small segment waits while anything is unacknowledged
                let all_queued_data_fits = len == unsent;
                if !self.nodelay && len < self.mss as usize && in_flight > 0 && !(self.fin_queued && all_queued_data_fits) {
                    break;
                }
                let payload: Vec<u8> = self.sendq.iter().skip(sent_data).take(len).copied().collect();
                let last = len == unsent;
                let seq = self.snd_nxt;
                self.advance_nxt(len as u32);
                if self.rtt_probe.is_none() && self.retries == 0 {
                    self.rtt_probe = Some((seq, now));
                }
                out.push(self.seg(ACK | if last { PSH } else { 0 }, seq, payload, false));
                if self.rto_at.is_none() {
                    self.rto_at = Some(now + self.rto);
                }
                self.ack_now = false;
                self.delack_at = None;
                self.unacked_rx = 0;
                continue;
            }
            // zero window with data waiting: probe (RFC 9293 3.8.6.1)
            if unsent > 0 && self.snd_wnd == 0 && in_flight == 0 {
                match self.persist_at {
                    None => self.persist_at = Some(now + self.rto),
                    Some(t) if now >= t => {
                        let payload: Vec<u8> = self.sendq.iter().skip(sent_data).take(1).copied().collect();
                        let seq = self.snd_nxt;
                        self.advance_nxt(1);
                        out.push(self.seg(ACK, seq, payload, false));
                        self.rto_at = Some(now + self.rto);
                        self.persist_at = None;
                    }
                    _ => {}
                }
            }
            if unsent == 0 && self.fin_queued && !self.fin_sent && matches!(self.state, State::Established | State::CloseWait) {
                self.fin_sent = true;
                let seq = self.snd_nxt;
                self.advance_nxt(1);
                out.push(self.seg(ACK | FIN, seq, Vec::new(), false));
                self.state = if self.state == State::Established { State::FinWait1 } else { State::LastAck };
                if self.rto_at.is_none() {
                    self.rto_at = Some(now + self.rto);
                }
                self.ack_now = false;
            } else if unsent == 0 && self.fin_sent && self.snd_nxt == self.fin_seq() && matches!(self.state, State::FinWait1 | State::LastAck | State::Closing) {
                // the FIN again, after a timeout
                let seq = self.snd_nxt;
                self.advance_nxt(1);
                out.push(self.seg(ACK | FIN, seq, Vec::new(), false));
                self.ack_now = false;
            }
            break;
        }
        if self.ack_now {
            self.ack_now = false;
            self.delack_at = None;
            self.unacked_rx = 0;
            // (a pure ACK carries the highest sequence number sent, not the point a timeout rewound to: the peer would
            // otherwise find it "old" and throw its acknowledgement away)
            out.push(self.seg(ACK, self.snd_max, Vec::new(), false));
        }
        out
    }

    fn seg(&mut self, flags: u8, seq: u32, payload: Vec<u8>, syn: bool) -> OutSeg {
        let window = self.advertise(syn);
        OutSeg {
            flags,
            seq,
            ack: self.rcv_nxt,
            window,
            mss: syn.then_some(self.cfg.mss),
            window_scale: (syn && (self.state == State::SynSent || self.peer_sent_syn_opts)).then_some(self.rcv_scale),
            payload,
        }
    }
}
