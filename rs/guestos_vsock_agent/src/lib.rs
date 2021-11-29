// This crate doesn't build on Mac because it depends on `vsock` which is only
// supported on Linux. Unfortunately, you can't conditionally include crates in
// a Cargo workspace based on what platform you're on, so we have to just make
// this an empty crate on Mac.
#![cfg(target_os = "linux")]

use std::os::raw::c_uint;

/// A vsock address spec.
#[derive(Clone, Copy, Debug)]
pub struct VsockAddr {
    /// vsock CID.
    pub cid: c_uint,
    /// vsock port.
    pub port: c_uint,
}

impl VsockAddr {
    /// Create a VsockAddr with the special VMADDR_CID_ANY CID and the provided
    /// port. This can be used to bind to the local vsock device for
    /// listening.
    pub fn any_cid_with_port(port: c_uint) -> Self {
        Self {
            cid: libc::VMADDR_CID_ANY,
            port,
        }
    }
}

pub mod client;
pub mod server;

pub use client::VsockStream;
