//! Allocate TCP/IP-addresses for nodes in a system or production test.
//!
//! This module contains two implementations of TcpAddressAllocator: One for
//! system tests, that binds addresses to localhost and let's the OS select an
//! ephemeral port. The other one for vm based tests where the address is
//! selected from a predefined set of Ip(v6) addressess. In the latter case, the
//! ports are currently hardcoded.
//!
//! Eventually, the goal is to support vm based tests only and, then,
//! TcpAddressAllocator will be obsolete.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
};

// A description of a specific address.
pub type AddrSpec = (TopologyPath, AddrType);
/// (SubnetIndex, NodeIndex), pair of indices pointing to a node in the topology
/// configuration.
pub type TopologyPath = (usize, usize);

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddrType {
    P2P,
    Xnet,
    PublicApi,
    Prometheus,
    NodemanagerPrometheus,
}

impl From<AddrType> for u16 {
    fn from(a: AddrType) -> Self {
        use AddrType::*;
        match a {
            P2P => 4100,
            Xnet => 2497,
            PublicApi => 8080,
            Prometheus => 9090,
            NodemanagerPrometheus => 9100,
        }
    }
}

/// A (possibly) stateful object that maps a pair of (subnet index, node index)
/// to a SocketAddr.
pub trait TcpAddrAllocator {
    /// During the lifetime of a TcpAddressAllocator it should hold any two
    /// calls to `get_addr` with the same arguments should return equal results.
    fn get_addr(&mut self, subnet_idx: usize, node_idx: usize, addr_type: AddrType) -> SocketAddr;
}

/// Let the operating system choose a port. All addresses are bound to the
/// IPv4-loopback address (`127.0.0.1`).
///
/// The implementation is kept as simple as possible, i.e., no additional flags,
/// such as REUSE_PORT, are set when binding a port (currently, we cannot make
/// use of them as the internal libraries don't set the flag)
pub struct EphemeralPortAllocator {
    memoized_addrs: BTreeMap<AddrSpec, SocketAddr>,
    listeners: Vec<TcpListener>,
}

impl EphemeralPortAllocator {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Default for EphemeralPortAllocator {
    fn default() -> Self {
        Self {
            memoized_addrs: Default::default(),
            listeners: vec![],
        }
    }
}

impl TcpAddrAllocator for EphemeralPortAllocator {
    fn get_addr(&mut self, subnet_idx: usize, node_idx: usize, addr_type: AddrType) -> SocketAddr {
        let addr_spec = ((subnet_idx, node_idx), addr_type);
        let listeners = &mut self.listeners;
        *self.memoized_addrs.entry(addr_spec).or_insert_with(|| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            listeners.push(listener);
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), addr.port())
        })
    }
}

pub struct VmAddrAllocator {
    memoized_addrs: BTreeMap<TopologyPath, IpAddr>,
    available_addresses: Vec<IpAddr>,
}

impl VmAddrAllocator {
    pub fn new(available_addresses: Vec<IpAddr>) -> Self {
        Self {
            memoized_addrs: Default::default(),
            available_addresses,
        }
    }
}

impl TcpAddrAllocator for VmAddrAllocator {
    fn get_addr(&mut self, subnet_idx: usize, node_idx: usize, addr_type: AddrType) -> SocketAddr {
        let path = (subnet_idx, node_idx);
        let addrs = &mut self.available_addresses;
        let addr = *self
            .memoized_addrs
            .entry(path)
            .or_insert_with(|| addrs.pop().expect("Too few addresses available"));
        let port: u16 = addr_type.into();
        SocketAddr::new(addr, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, net::Ipv6Addr};

    #[test]
    fn all_ephemeral_addr_are_unique_and_memoized() {
        const N: usize = 3;
        let mut addr_allocator = EphemeralPortAllocator::default();
        t(N, &mut addr_allocator);
    }

    #[test]
    fn all_vm_addr_are_unique_and_memoized() {
        const N: usize = 3;

        let ip_addrs: Vec<_> = (0..N * N + 1)
            .map(|i| IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, i as u16)))
            .collect();
        let mut addr_allocator = VmAddrAllocator::new(ip_addrs);

        t(N, &mut addr_allocator);
    }

    fn t(n: usize, addr_allocator: &mut dyn TcpAddrAllocator) {
        use AddrType::*;

        let addr_types: &[AddrType] = &[P2P, Xnet, PublicApi, Prometheus, NodemanagerPrometheus];
        let combinations: Vec<_> = (0..n)
            .flat_map(|s| {
                (0..n).flat_map(move |n| addr_types.iter().map(move |at| (n, s, at.clone())))
            })
            .collect();

        let mut get_addrs = || {
            combinations
                .iter()
                .map(|(s, n, a)| addr_allocator.get_addr(*s, *n, a.clone()))
                .collect::<BTreeSet<_>>()
        };

        let set0 = get_addrs();
        assert_eq!(set0.len(), combinations.len());
        // aksing for the same addresses again will yields the same result.
        let set1 = get_addrs();
        assert_eq!(set0, set1);

        let addr = addr_allocator.get_addr(n, n + 1, Xnet);
        assert!(!set0.contains(&addr));
    }
}
