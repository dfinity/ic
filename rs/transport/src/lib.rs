//! Transport component for the internet computer
//!
//! <h1>Overview</h1>
//!
//! The transport layer implements the functionality to:
//!
//! * Manage connections with peers
//! * Exchange messages with peers
//! * DOS protection and receive-side scheduling
//!
//! <h1>Preliminaries</h1>
//!
//! The purpose of the transport component is to move messages created by a
//! client component on one node to the same component of another node. Pairs of
//! nodes communicating with each other (*peers*) may be part of (i) the same
//! subnet for gossip or may (ii) operate on different subnets for xnet
//! messaging*.
//!
//! Messages in the first class include Ingress, Consensus, DKG, Certification
//! and State Sync messages. The transport client for these messages is P2P.
//! Messages sent from one subnet to another are Xnet messages, the transport
//! client for these is Message Routing. Traffic from users to a node (e.g., for
//! installing or updating a canister) is not sent over transport.
//!
//! Transport processes different types of messages classified into *flows* by
//! their QoS requirements.  The same flow id and weight is used for both
//! incoming (RX)  and outgoing (TX) messages of the same type, between two
//! peers.
//!
//! Gossip uses separate flows for control messages (adverts, requests) and data
//! messages (artifact chunks), for ingress manager, consensus (incl DKG and
//! certification) and state sync. Thus, Transport has to handle 3 x 3 flows per
//! peer for Gossip.

mod control_plane;
mod data_plane;
mod metrics;
pub mod transport;
mod types;
mod utils;
