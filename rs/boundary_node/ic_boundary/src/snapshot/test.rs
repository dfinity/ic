use super::*;
use crate::test_utils::{create_fake_registry_client, valid_tls_certificate_and_validation_time};
use ic_registry_routing_table::CanisterIdRange;

#[allow(clippy::type_complexity)]
pub fn test_registry_snapshot(
    subnets: usize,
    nodes_per_subnet: usize,
) -> (
    RegistrySnapshot,
    Vec<(NodeId, String)>,
    Vec<(SubnetId, CanisterIdRange)>,
) {
    let snapshot = Arc::new(ArcSwapOption::empty());

    let (reg, nodes, ranges) = create_fake_registry_client(subnets, nodes_per_subnet, None);
    let reg = Arc::new(reg);

    let (channel_send, _) = watch::channel(None);
    let mut snapshotter =
        Snapshotter::new(Arc::clone(&snapshot), channel_send, reg, Duration::ZERO);
    snapshotter.snapshot().unwrap();

    (
        snapshot.load_full().unwrap().as_ref().clone(),
        nodes,
        ranges,
    )
}

#[tokio::test]
async fn test_routing_table() -> Result<(), Error> {
    let (snapshot, nodes, ranges) = test_registry_snapshot(4, 1);

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
