use super::*;

use std::{str::FromStr, time::Duration};

use anyhow::Error;

use crate::{
    core::Run,
    snapshot::{
        test::{create_fake_registry_client, create_nodes},
        Runner,
    },
};

// Check that resolver yields correct IPs
#[tokio::test]
async fn test_resolve() -> Result<(), Error> {
    use hyper::client::connect::dns::Name;

    let reg = Arc::new(create_fake_registry_client(4));
    let rt = Arc::new(ArcSwapOption::empty());
    let helper = DnsResolver::new(Arc::clone(&rt));
    let mut runner = Runner::new(Arc::clone(&rt), reg, Duration::ZERO);
    runner.run().await?;

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
