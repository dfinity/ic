//! # The Titanium Prometheus Service Discovery Daemon
//!
//! The multi-target prometheus service discovery daemon is a rewrite of the
//! original ic_p8s_service_discovery. The two major features it provides over
//! it predecessor are
//!
//! * robustness in case of outages, as the registry is persisted. In
//! particular, the configuration of the daemon itself is kept up-to-date in
//! this way.
//!
//! * Dynamic target acquisition: Observing dynamically changing set of (test)
//! Internet Computer instances. (not yet implemented)
//!
//! ## Architecture
//!
//!
//!  +---------+    .- ic-p8s-sd ---------------.
//!  |  Farm   |    .                           .
//!  |  /group | -->->--(target_acquisition)    .
//!  +---------+    .           |               .
//!                 .           v               .
//!                 .           |               .
//!                 .  +-------------------+    .
//!                 .  | discovery_targets |    .
//!                 .  +-------------------+    .
//!                 .           |               .
//!                 .           v               .
//!                 .           v               .
//!                 .           |               .
//!                 .      (IcDiscovery)        .
//!                 .           |               .
//!                 .           v               .
//!                 .           v               .
//!                 .           |               .
//!                 .       (rest_api)          .
//!                 ........... |  ..............
//!                             v
//!                             v
//!                           (p8s)
//!
//! ->>- receiving component pulls/reads
//! ->-- receiving component pushes/writes
//!
//! `discovery_targets` is logically a mapping from a name to a registry state.
//! It is represented as a directory containing one directory per name/registry.
//! The registry is represented as local store.
//!
//! For example, the registry of the mainnet instance (traditionally called
//! 'mercury') would be placed under <discovery_targets>/mercury.
//!
//! *Note*: As of now, dynamic target acquisition is not implemented.

pub mod titanium;
