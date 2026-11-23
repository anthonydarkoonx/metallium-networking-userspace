//! The Metallium-OS network service and its driver, as user-space code: `netd` (role 19, the IP stack of `metallium-net` behind an
//! IPC endpoint), `netdrv` (role 18, the virtio-net driver) and `httpc` (a plain HTTP client over the service). The OS's user image
//! links this crate in and starts the two roles by number (`user/src/main.rs`); nothing here is in the kernel.
#![no_std]

extern crate alloc;

pub mod httpc;
pub mod netd;
pub mod netdrv;
