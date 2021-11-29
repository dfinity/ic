//! Let the operating system allocate ephemeral tcp ports.
//!
//! The implementation is kept as simple as possible, i.e., no additional flags,
//! such as REUSE_PORT, are set when binding a port (currently, we cannot make
//! use of them as the internal libraries don't set the flag)
use std::net::{SocketAddr, TcpListener};

pub struct TcpPortAllocator {
    listener: Vec<TcpListener>,
}

impl TcpPortAllocator {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Default for TcpPortAllocator {
    fn default() -> Self {
        Self { listener: vec![] }
    }
}

// Note: This should probably be renamed to TcpAddressAllocator or
// TcpSocketAllocator
impl Iterator for TcpPortAllocator {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        self.listener.push(listener);
        Some(addr)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    #[ignore]
    #[test]
    fn all_ports_are_unique() {
        use super::*;

        let sample_size = 10;
        let port_allocator = TcpPortAllocator::default();
        let ports: BTreeSet<_> = port_allocator.take(sample_size).collect();

        assert_eq!(ports.len(), sample_size);
    }
}
