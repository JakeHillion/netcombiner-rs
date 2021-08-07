# Rust Implementation of NetCombiner

## Usage

To add an interface with netcombiner-rs, run:

    $ netcombiner-rs nc0

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del nc0`,
or if your system does not support removing interfaces directly, you may instead remove the control socket via
`rm -f /var/run/netcombiner/nc0.sock`, which will result in netcombiner-rs shutting down.

When an interface is running, you may use `netcombiner(8)` to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

## Description

NetCombiner balances packets between multiple paths using congestion control to
determine the best balance.

The primary use case for this is combining multiple discrete Internet connections
into one larger connection. The new connection has both the combined bandwidth of
the two connections and the combined uptime, at the cost of increased latency.

## Platforms

### Linux

Tested primarily on Linux.

### Windows

Coming soon.

### FreeBSD

Coming soon.

### OpenBSD

Coming soon.

## Building

The netcombiner-rs project is targeting the current stable rust.

To build netcombiner-rs (on supported platforms):

1. Obtain stable `cargo` and `rustc` through [rustup](https://rustup.rs/)
2. Clone the repository: `git clone https://github.com/JakeHillion/netcombiner-rs.git`.
3. Run `cargo build --release` from inside the `netcombiner-rs` directory.

## Architecture

This section is intended for those wishing to read/contribute to the code.

NetCombiner Rust is based on [WireGuard Rust](https://git.zx2c4.com/wireguard-rs).
The primary changes are in the routing of packets. While WireGuard has multiple
peers that each present IPs, NetCombiner has a single peer with multiple routes.
Each packet's routing is decided by congestion control as opposed to reaching the
packet's destination IP.

