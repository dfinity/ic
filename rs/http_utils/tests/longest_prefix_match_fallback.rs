use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use reqwest::{
    dns::{Addrs, Name, Resolve, Resolving},
    redirect::Policy,
    Client,
};

/// Test resolver that always returns a set of static IPv6 addresses: all but the last one are
/// unreachable, while the last one is reachable.
/// This is used to test the fallback mechanism of the resolver. The request should try the first
/// addresses, fail, retry until `tcp_syn_retries` is exhausted (Linux default is 6), going to the
/// next ones, retry, refail, and finally fall back and succeed with the last address
///
/// The time elapsed for 6 `tcp_syn_retries` is approximately 131 seconds.
/// Source: https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html#tcp-syn-retries
///
/// Every unreachable address should thus make the client stuck for approximately 131 seconds. In
/// practice though, we mostly observed around 134-135 seconds (probably due to a OS-specific
/// configuration), so we use 134 seconds as the expected time for the unreachable addresses (see
/// the test below).
struct TestResolver {
    pub nb_unreachable: usize,
}

// dns.google, will always exist, but port 80 is filtered out, so SYNs will be dropped
const UNREACHABLE: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x0, 0x0, 0x0, 0x0, 0x8888);
// one.one.one.one, will always exist, and port 80 is open
const REACHABLE: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0x0, 0x0, 0x0, 0x0, 0x1111);

impl Resolve for TestResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        let nb_unreachable = self.nb_unreachable;

        Box::pin(async move {
            // n unreachable addresses, then a reachable address
            let iter = std::iter::repeat_n(UNREACHABLE, nb_unreachable)
                .chain(std::iter::once(REACHABLE))
                .map(|ip| SocketAddr::new(IpAddr::V6(ip), 0));

            Ok(Box::new(iter) as Addrs)
        })
    }
}

#[tokio::test]
async fn test_unreachable_addr_falls_back_to_next_reachable() {
    // Number of unreachable addresses to simulate
    let nb_unreachable = 3_u64;

    // Unreachable addresses should take 134 +- 5 seconds before giving up. Reachable addresses
    // should take 0-2 seconds to respond.
    // These values were found by trial and error. Feel free to adjust them if the test is flaky,
    // for example by increasing the grace period.
    let expected_unreachable = 134_u64;
    let grace_unreachable = 5_u64;
    let max_reachable = 2_u64;

    let client = Client::builder()
        .dns_resolver(Arc::new(TestResolver {
            nb_unreachable: nb_unreachable as usize,
        }))
        .redirect(Policy::none()) // Disable redirect to HTTPS
        .build()
        .expect("Failed to create HTTP client");

    let timer = Instant::now();
    let response = client
        .get("http://one.one.one.one")
        .send()
        .await
        .expect("Failed to send request");
    let elapsed = timer.elapsed().as_secs();

    assert_eq!(
        response.remote_addr().expect("No remote address found"),
        SocketAddr::new(IpAddr::V6(REACHABLE), 80)
    );

    // Specific to http://one.one.one.one, which redirects to HTTPS
    assert!(
        response.status().is_redirection(),
        "Expected a redirection to HTTPS, but got status {}",
        response.status()
    );

    let expected_range = nb_unreachable * (expected_unreachable - grace_unreachable)
        ..=nb_unreachable * (expected_unreachable + grace_unreachable) + max_reachable;
    assert!(
        expected_range.contains(&elapsed),
        "Expected elapsed time to be within {:?}, but got {} seconds",
        expected_range,
        elapsed
    );
}
