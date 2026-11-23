# metallium-networking-userspace

The networking of [Metallium-OS](https://github.com/anthonydarkoonx/metallium-os), all of it user-space code: the IP stack, the
network service, the network driver, the client API and the tests. The kernel has only the generic mechanisms (the device's
MMIO and DMA objects, the per-program session pages, the `R_SPAWN_NET` right); nothing of the protocols is in it.
Licensed Apache-2.0 OR MIT.

## Layout
| path | what |
|---|---|
| `crates/metallium-net` | the stack, written from the RFCs: Ethernet, ARP, IPv4 with reassembly, ICMP echo, UDP, TCP (RFC 9293, NewReno, window scaling), a DHCP client and a DNS resolver. `no_std`, `#![forbid(unsafe_code)]`, owns no clock and no device: the caller passes the time, feeds frames in and takes frames out. Host-tested (`cargo test`) |
| `crates/metallium-net-ring` | the ring page and packet buffers the driver and the service share (`netring`), and the message word between them. `no_std`, no dependencies |
| `services/` | crate `metallium-net-services`: `netd` (role 19, the stack behind an IPC endpoint, session protocol in the OS's `docs/ABI.md`), `netdrv` (role 18, the virtio-net driver over PCI; the only device-specific code) and `httpc` (a plain HTTP client). The OS's user image links the crate in and starts the two roles by number |
| `client/net.rs` | the client API programs use: UDP sockets, TCP streams and listeners, name lookup, ping |
| `programs/` | `nettest` (the network tests, run against the host peer), `netcheck` and `fetch` |
| `tools/` | `netpeer.py`, the host side of the network tests, and `with-peer.sh`, which runs a command (QEMU) with the peer alive |

## Building and testing
This repository and the OS repository must sit **side by side** (`~/Desktop/metallium-os` and
`~/Desktop/metallium-networking-userspace`, say): the manifests refer to each other by relative path
(`../metallium-os` here, `../../metallium-networking-userspace` there), so that each crate exists once in a build.

    cargo test --workspace      # here: the stack's host tests, the ring layout, and a check that the service crate compiles on the host
    make quick-net              # in the OS repository: boots QEMU against tools/netpeer.py and runs just the network tests
    make test                   # in the OS repository: everything, the network tests included

`services/` depends on `metallium-driver-rt` (system calls, `println!`, mappings, virtio) from the OS repository.
`client/net.rs` and `programs/*.rs` are not crates of their own: the OS's `programs` crate includes the client as its `net` module
and builds the three programs as `[[bin]]` entries (its `build.rs` and linker scripts make them position-independent images), because
they need that crate's `io`, `thread` and `program!` and cannot be a dependency of it.

## A different network device
Only `services/src/netdrv.rs` knows virtio. A driver for another NIC takes its place by keeping the ring contract of
`metallium-net-ring`: frames cross the rings with a 12-byte header in front (the virtio-net header; another driver leaves it zeroed).
The Radxa ROCK 3C port ([metallium-os-rock3c](https://github.com/anthonydarkoonx/metallium-os-rock3c)) replaces `netdrv` this way.
