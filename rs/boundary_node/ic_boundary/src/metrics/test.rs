use super::*;

use crate::check::test::generate_custom_registry_snapshot;
use prometheus::proto::{LabelPair, Metric};

// node_id, subnet_id
const NODES: &[(&str, &str)] = &[
    ("y7s52-3xjam-aaaaa-aaaap-2ai", "fscpm-uiaaa-aaaaa-aaaap-yai"),
    ("ftjgm-3pkam-aaaaa-aaaap-2ai", "fscpm-uiaaa-aaaaa-aaaap-yai"),
    ("fat3m-uhiam-aaaaa-aaaap-2ai", "fscpm-uiaaa-aaaaa-aaaap-yai"),
    ("fat3m-uhiam-aaaaa-aaaap-2ai", "ascpm-uiaaa-aaaaa-aaaap-yai"), // node in snapshot, but in different subnet
    ("fat3n-uhiam-aaaaa-aaaap-2ai", "fscpm-uiaaa-aaaaa-aaaap-yai"), // node not in snapshot
    ("fat3o-uhiam-aaaaa-aaaap-2ai", "fscpm-uiaaa-aaaaa-aaaap-yai"), // node not in snapshot
];

fn gen_metric(node_id: Option<String>, subnet_id: Option<String>) -> Metric {
    let mut m = Metric::new();

    let mut lbl = LabelPair::new();
    lbl.set_name("foo".into());
    lbl.set_value("bar".into());

    let mut lbls = vec![lbl];

    if let Some(v) = node_id {
        let mut lbl = LabelPair::new();
        lbl.set_name(NODE_ID_LABEL.into());
        lbl.set_value(v);
        lbls.push(lbl);
    }

    if let Some(v) = subnet_id {
        let mut lbl = LabelPair::new();
        lbl.set_name(SUBNET_ID_LABEL.into());
        lbl.set_value(v);
        lbls.push(lbl);
    }

    m.set_label(lbls.into());

    m
}

fn gen_metric_family(
    name: String,
    nodes: &[(&str, &str)],
    add_node_id: bool,
    add_subnet_id: bool,
) -> MetricFamily {
    let metrics = nodes
        .iter()
        .map(|&(node_id, subnet_id)| {
            gen_metric(
                if add_node_id {
                    Some(node_id.into())
                } else {
                    None
                },
                if add_subnet_id {
                    Some(subnet_id.into())
                } else {
                    None
                },
            )
        })
        .collect::<Vec<_>>();

    let mut mf = MetricFamily::new();
    mf.set_name(name);
    mf.set_metric(metrics.into());
    mf
}

fn gen_metric_families() -> Vec<MetricFamily> {
    let mut mfs = Vec::new();

    // These are with both labels defined
    for n in &["foobar", "foobaz", "fooboo"] {
        mfs.push(gen_metric_family((*n).into(), NODES, true, true));
    }

    // These with one of them
    mfs.push(gen_metric_family("boo".into(), NODES, false, true));
    mfs.push(gen_metric_family("goo".into(), NODES, true, false));

    // This without both them
    mfs.push(gen_metric_family("zoo".into(), NODES, false, false));

    mfs
}

#[test]
fn test_remove_stale_metrics() -> Result<(), Error> {
    // subnet id: fscpm-uiaaa-aaaaa-aaaap-yai
    // node ids in a snapshot:
    // - y7s52-3xjam-aaaaa-aaaap-2ai
    // - ftjgm-3pkam-aaaaa-aaaap-2ai
    // - fat3m-uhiam-aaaaa-aaaap-2ai
    let snapshot = Arc::new(generate_custom_registry_snapshot(1, 3, 0));
    let mfs = remove_stale_metrics(Arc::clone(&snapshot), gen_metric_families());
    assert_eq!(mfs.len(), 6);

    let mut only_node_id = 0;
    let mut only_subnet_id = 0;
    let mut no_ids = 0;

    // Check that the metric families now contain only metrics with node_id+subnet_id from the snapshot
    // and other metrics are untouched
    for mf in mfs {
        for m in mf.get_metric() {
            let node_id = m
                .get_label()
                .iter()
                .find(|&v| v.get_name() == NODE_ID_LABEL)
                .map(|x| x.get_value());

            let subnet_id = m
                .get_label()
                .iter()
                .find(|&v| v.get_name() == SUBNET_ID_LABEL)
                .map(|x| x.get_value());

            match (node_id, subnet_id) {
                (Some(node_id), Some(subnet_id)) => assert!(snapshot
                    .nodes
                    .get(node_id)
                    .map(|x| x.subnet_id.to_string() == subnet_id)
                    .unwrap_or(false)),

                (Some(_), None) => only_node_id += 1,
                (None, Some(_)) => only_subnet_id += 1,
                _ => no_ids += 1,
            }
        }
    }

    assert_eq!(only_node_id, NODES.len());
    assert_eq!(only_subnet_id, NODES.len() - 1);
    assert_eq!(no_ids, NODES.len());

    Ok(())
}
