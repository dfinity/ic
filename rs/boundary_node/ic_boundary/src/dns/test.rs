use super::*;

use std::{str::FromStr, time::Duration};

use anyhow::Error;

use crate::{
    snapshot::{Snapshot, Snapshotter},
    test_utils::create_fake_registry_client,
};

// Check that resolver yields correct IPs
#[tokio::test]
async fn test_resolve() -> Result<(), Error> {
    use reqwest::dns::Name;

    let (reg, nodes, _) = create_fake_registry_client(4, 1, None);
    let reg = Arc::new(reg);
    let snapshot = Arc::new(ArcSwapOption::empty());
    let dns_resolver = DnsResolver::new(Arc::clone(&snapshot));

    let (channel_send, _) = tokio::sync::watch::channel(None);
    let mut snapshotter =
        Snapshotter::new(Arc::clone(&snapshot), channel_send, reg, Duration::ZERO);
    snapshotter.snapshot()?;

    // Check that resolved node's IPs match expected ones
    for node in nodes.into_iter() {
        let res = dns_resolver
            .resolve(Name::from_str(node.0.to_string().as_str()).unwrap())
            .await;

        match res {
            Ok(mut r) => {
                assert_eq!(r.next().unwrap().clone().ip().to_string(), node.1);
            }

            Err(_) => {
                panic!("should not error out")
            }
        }
    }

    // Check the lookup failure for unknown node name
    let res = dns_resolver
        .resolve(Name::from_str("foo-bar-baz").unwrap())
        .await;
    assert!(res.is_err());

    Ok(())
}
