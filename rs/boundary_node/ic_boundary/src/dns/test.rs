use super::*;

use std::{str::FromStr, time::Duration};

use anyhow::Error;

use crate::snapshot::{
    test::{create_fake_registry_client, create_nodes},
    Snapshot, Snapshotter,
};

// Check that resolver yields correct IPs
#[tokio::test]
async fn test_resolve() -> Result<(), Error> {
    use hyper::client::connect::dns::Name;

    let reg = Arc::new(create_fake_registry_client(4));
    let snapshot = Arc::new(ArcSwapOption::empty());
    let helper = DnsResolver::new(Arc::clone(&snapshot));
    let mut snapshotter = Snapshotter::new(Arc::clone(&snapshot), reg, Duration::ZERO);
    snapshotter.snapshot().await?;

    // Check that resolved node's IPs match expected ones
    let nodes = create_nodes();

    for node in nodes.into_iter() {
        let res = helper.resolve(Name::from_str(node.0).unwrap()).await;

        match res {
            Ok(mut r) => {
                assert_eq!(r.next().unwrap().clone().ip(), node.1);
            }

            Err(_) => {
                panic!("should not error out")
            }
        }
    }

    // Check the lookup failure for unknown node name
    let res = helper.resolve(Name::from_str("foo-bar-baz").unwrap()).await;
    assert!(matches!(res, Result::Err(_)));

    Ok(())
}
