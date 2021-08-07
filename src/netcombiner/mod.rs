/// The netcombiner sub-module represents a full, pure, NetCombiner implementation:
///
/// The NetCombiner device described here does not depend on particular IO implementations
/// or UAPI, and can be instantiated in unit-tests with the dummy IO implementation.
///
/// The code at this level serves to "glue" the handshake state-machine
/// and the crypto-key router code together,
/// e.g. every NetCombiner peer consists of one handshake peer and one router peer.
mod constants;
mod handshake;
mod peer;
mod queue;
mod router;
mod timers;
mod types;
mod workers;

#[cfg(test)]
mod tests;

#[allow(clippy::module_inception)]
mod netcombiner;

// represents a NetCombiner interface
pub use netcombiner::NetCombiner;

#[cfg(test)]
use super::platform::dummy;

use super::platform::{tun, udp, Endpoint};
use types::KeyPair;
