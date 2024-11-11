use anyhow::Result;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use ic_tests::boundary_nodes::performance_test::{empty_setup, mainnet_query_calls_test};
use std::{env, net::Ipv6Addr, time::Duration};

fn main() -> Result<()> {
    let ipv6 = env::var("BOUNDARY_NODE_IPV6").expect("environment variable is not provided");
    let bn_ipv6 = ipv6.parse::<Ipv6Addr>().expect("invalid ipv6");
    let test = move |env| mainnet_query_calls_test(env, bn_ipv6);
    SystemTestGroup::new()
        .with_setup(empty_setup)
        .add_test(systest!(test))
        .with_timeout_per_test(Duration::from_secs(140 * 60))
        .execute_from_args()?;
    Ok(())
}
