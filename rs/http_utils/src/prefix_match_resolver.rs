use hyper_util::client::legacy::connect::dns::GaiResolver;
use reqwest::dns::{Name, Resolve, Resolving};
use std::{
    cmp,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tower_service::Service;

pub(crate) struct LongestPrefixMatchResolver(GaiResolver);

impl LongestPrefixMatchResolver {
    pub fn new() -> Self {
        Self(GaiResolver::new())
    }
}

/// This resolver is used to resolve domain names and sort the resulting IP addresses by longest
/// prefix match. It first uses the default `GaiResolver` before applying the sorting logic. It
/// prioritizes IPv6 addresses over IPv4 addresses.
impl Resolve for LongestPrefixMatchResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let mut this = self.0.clone();

        Box::pin(async move {
            // Resolve with `GaiResolver`, which is the default resolver in reqwest.
            let resolved_addrs = this
                .call(name.as_str().parse()?)
                .await?
                .map(|saddr| saddr.ip())
                .collect::<Vec<_>>();

            let local_addrs = local_ip_address::list_afinet_netifas()?
                .into_iter()
                .map(|(_, ip)| ip)
                .collect::<Vec<_>>();
            // Sort the resolved addresses by longest prefix match, putting IPv6 addresses first
            let sorted_sock_addrs = sort_by_longest_prefix_match(resolved_addrs, local_addrs)
                .into_iter()
                .map(|addr| SocketAddr::new(addr, 0));

            Ok(Box::new(sorted_sock_addrs) as Box<dyn Iterator<Item = SocketAddr> + Send>)
        })
    }
}

/// Returns the same set of given resolved IP addresses, but with all IPv6 addresses first, then all
/// IPv4 addresses each respectively sorted by longest prefix match, with respect to the given local
/// IP addresses.
fn sort_by_longest_prefix_match(
    resolved_addrs: Vec<IpAddr>,
    local_addrs: Vec<IpAddr>,
) -> Vec<IpAddr> {
    let (mut resolved_v4s, mut resolved_v6s) = grouped_by_prot(
        resolved_addrs,
        true, // Keep resolved loopback addresses (in case of localhost resolution, f.ex.)
    );

    let (local_v4s, local_v6s) = grouped_by_prot(
        local_addrs,
        false, // Do not match loopback addresses
    );

    resolved_v4s.sort_by_key(|resolved_v4| {
        cmp::Reverse(
            local_v4s
                .iter()
                .map(|client_v4| {
                    nb_leading_matching_bits(&client_v4.octets(), &resolved_v4.octets())
                })
                .max(),
        )
    });
    resolved_v6s.sort_by_key(|resolved_v6| {
        cmp::Reverse(
            local_v6s
                .iter()
                .map(|client_v6| {
                    nb_leading_matching_bits(&client_v6.octets(), &resolved_v6.octets())
                })
                .max(),
        )
    });

    // Return IPv6 then IPv4
    resolved_v6s
        .into_iter()
        .map(IpAddr::V6)
        .chain(resolved_v4s.into_iter().map(IpAddr::V4))
        .collect()
}

/// Splits a vector of IP addresses by protocol, IPv4 and IPv6.
fn grouped_by_prot(addrs: Vec<IpAddr>, keep_lo: bool) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    let mut v4s = vec![];
    let mut v6s = vec![];

    for addr in addrs {
        if !keep_lo && addr.is_loopback() {
            continue;
        }

        match addr {
            IpAddr::V4(v4) => v4s.push(v4),
            IpAddr::V6(v6) => v6s.push(v6),
        }
    }

    (v4s, v6s)
}

/// Counts the number of matching bits between two slices of bytes.
fn nb_leading_matching_bits(a: &[u8], b: &[u8]) -> u32 {
    let mut matching_bits = 0;
    for (octet_a, octet_b) in a.iter().zip(b.iter()) {
        let diff = octet_a ^ octet_b;
        let mut mask = 0x80; // Start with the most significant bit

        for _ in 0..8 {
            if diff & mask == 0 {
                matching_bits += 1; // Count matching bits
            } else {
                return matching_bits; // Stop at the first non-matching bit
            }
            mask >>= 1; // Move to the next bit
        }
    }

    matching_bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nb_leading_matching_bits() {
        assert_eq!(
            nb_leading_matching_bits(
                &Ipv4Addr::new(192, 168, 1, 1).octets(),
                &Ipv4Addr::new(192, 168, 1, 2).octets()
            ),
            30
        );
        assert_eq!(
            nb_leading_matching_bits(
                &Ipv4Addr::new(192, 168, 1, 1).octets(),
                &Ipv4Addr::new(64, 168, 1, 1).octets()
            ),
            0
        );
        assert_eq!(
            nb_leading_matching_bits(
                &Ipv6Addr::new(0x2602, 0xfb2b, 0x100, 0x10, 0x0, 0x0, 0x0, 0x0).octets(),
                &Ipv6Addr::new(0x2602, 0xfb2b, 0x110, 0x10, 0x0, 0x0, 0x0, 0x1).octets()
            ),
            43
        );
        assert_eq!(
            nb_leading_matching_bits(
                &Ipv6Addr::new(0x2a00, 0xfb01, 0x400, 0x42, 0x0, 0x0, 0x0, 0x0).octets(),
                &Ipv6Addr::new(0x2a00, 0xfb01, 0x400, 0x42, 0xffff, 0x1, 0x2, 0x3).octets()
            ),
            64
        );
    }

    #[test]
    fn test_sort_by_longest_prefix_match() {
        let resolved_addrs = vec![
            IpAddr::V4(Ipv4Addr::new(13, 107, 246, 60)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2603, 0x1010, 0x3, 0x3, 0x0, 0x0, 0x0, 0x5b)),
            IpAddr::V6(Ipv6Addr::new(
                0x1234, 0x5678, 0x0, 0x0, 0x0, 0x0, 0x0, 0xabcd,
            )),
            IpAddr::V6(Ipv6Addr::new(
                0x0, 0x0, 0x0, 0x0, 0x0, 0xffff, 0xc0a8, 0x0101,
            )),
            IpAddr::V6(Ipv6Addr::new(
                0xfd12, 0x3456, 0x789a, 0x0, 0x0, 0x0, 0x0, 0x1,
            )),
        ];
        let local_addrs = vec![
            IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), // will be ignored (loopback)
            IpAddr::V4(Ipv4Addr::new(192, 168, 122, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1)),
            IpAddr::V6(Ipv6Addr::new(0xfd10, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x2)),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0x0, 0x0, 0x0, 0xabcd, 0xef, 0x0, 0x1)),
            IpAddr::V6(Ipv6Addr::new(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1)), // will be ignored
                                                                               // (loopback)
        ];

        let sorted_addrs = sort_by_longest_prefix_match(resolved_addrs.clone(), local_addrs);

        assert_eq!(sorted_addrs.len(), resolved_addrs.len());

        // IPv6 addresses should come first
        // fd12:3456:789a::1 with fd10:0:2::2 (14 bits match)
        assert_eq!(sorted_addrs[0], resolved_addrs[5]);
        // 2603:1010:3:3::5b with 2001:db8:1::1 (5 bits match)
        assert_eq!(sorted_addrs[1], resolved_addrs[2]);
        // 1234:5678::abcd with 2001:db8:1::1 (2 bits match)
        assert_eq!(sorted_addrs[2], resolved_addrs[3]);
        // ::ffff:c0a8:101 with 2001:db8:1::1 (2 bits match)
        assert_eq!(sorted_addrs[3], resolved_addrs[4]);
        // 172.16.0.1 with 172.17.0.1 (15 bits match)
        assert_eq!(sorted_addrs[4], resolved_addrs[1]);
        // 13.107.246.60 with 10.0.2.2 (5 bits match)
        assert_eq!(sorted_addrs[5], resolved_addrs[0]);
    }
}
