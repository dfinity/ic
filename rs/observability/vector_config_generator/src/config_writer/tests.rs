use std::{net::SocketAddrV6, str::FromStr};

use ic_types::{NodeId, PrincipalId, SubnetId};

use std::collections::BTreeSet;

#[test]
fn try_from_prometheus_target_group_to_vector_config_correct_inputs() {
    let original_addr = "[2a02:800:2:2003:5000:f6ff:fec4:4c86]:9091";
    let mut targets = BTreeSet::new();
    targets.insert(std::net::SocketAddr::V6(
        SocketAddrV6::from_str(original_addr).unwrap(),
    ));
    let ptg = TargetGroup {
        node_id: NodeId::from(
            PrincipalId::from_str(
                "iylgr-zpxwq-kqgmf-4srtx-o4eey-d6bln-smmq6-we7px-ibdea-nondy-eae",
            )
            .unwrap(),
        ),
        ic_name: "mercury".into(),
        targets,
        subnet_id: Some(SubnetId::from(
            PrincipalId::from_str(
                "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
            )
            .unwrap(),
        )),
    };

    let mut tg_map = BTreeSet::new();
    tg_map.insert(ptg);

    let vector_config = VectorServiceDiscoveryConfigEnriched::from(tg_map);
    dbg!(&vector_config);
    let config_endpoint = vector_config
        .sources
        .get(&String::from(String::from(original_addr) + "-source"));
    dbg!(config_endpoint);

    if let Some(conf) = config_endpoint {
        assert_eq!(
            conf.endpoints[0],
            url::Url::parse(&String::from(String::from("http://") + original_addr))
                .unwrap()
                .to_string()
        )
    }
}
