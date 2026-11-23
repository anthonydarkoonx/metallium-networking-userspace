//! A network stack written from the RFCs for Metallium-OS: Ethernet, ARP, IPv4 (with reassembly), ICMP echo, UDP, TCP (RFC 9293
//! with NewReno congestion control and window scaling), a DHCP client and a DNS resolver. The stack owns no clock and no
//! device: the caller passes the time in milliseconds, feeds frames in with `Stack::rx`, takes frames out with
//! `Stack::pop_tx`, and calls `Stack::poll` when `Stack::next_timer` says so.
#![forbid(unsafe_code)]
#![no_std]
extern crate alloc;

pub mod stack;
pub mod tcp;
pub mod wire;

pub use stack::{DnsResult, EchoReply, IpConfig, Io, NetError, Stack};

#[cfg(test)]
mod tests;
