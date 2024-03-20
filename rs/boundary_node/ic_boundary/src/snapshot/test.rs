use super::*;

use ic_crypto_test_utils_keys::public_keys::valid_tls_certificate_and_validation_time;

use crate::test_utils::create_fake_registry_client;

#[tokio::test]
async fn test_routing_table() -> Result<(), Error> {
    let snapshot = Arc::new(ArcSwapOption::empty());

    let (reg, nodes, ranges) = create_fake_registry_client(4, 1, None);
    let reg = Arc::new(reg);

    let (channel_send, _) = watch::channel(None);
    let mut snapshotter =
        Snapshotter::new(Arc::clone(&snapshot), channel_send, reg, Duration::ZERO);
    snapshotter.snapshot()?;
    let snapshot = snapshot.load_full().unwrap();

    assert_eq!(snapshot.version, 1);
    assert_eq!(snapshot.subnets.len(), 4);

    for i in 0..snapshot.subnets.len() {
        let sn = &snapshot.subnets[i];
        assert_eq!(sn.id.to_string(), ranges[i].0.to_string());

        assert_eq!(sn.ranges.len(), 1);
        assert_eq!(
            sn.ranges[0].start.to_string(),
            ranges[i].1.start.to_string()
        );
        assert_eq!(sn.ranges[0].end.to_string(), ranges[i].1.end.to_string());

        assert_eq!(sn.nodes.len(), 1);
        assert_eq!(sn.nodes[0].id.to_string(), nodes[i].0.to_string());
        assert_eq!(sn.nodes[0].addr.to_string(), nodes[i].1);

        assert_eq!(
            sn.nodes[0].tls_certificate,
            valid_tls_certificate_and_validation_time()
                .0
                .certificate_der,
        );
    }

    Ok(())
}
