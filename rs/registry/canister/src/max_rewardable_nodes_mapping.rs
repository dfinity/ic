use ic_base_types::PrincipalId;
use ic_protobuf::registry::node::v1::NodeRewardType;
use lazy_static::lazy_static;
use maplit::btreemap;
use std::collections::BTreeMap;
use std::str::FromStr;

lazy_static! {
    // TODO(DRE-625): Remove one-off migration
    pub static ref MAX_REWARDABLE_NODES_SWISS_SUBNET_NO: BTreeMap<PrincipalId, BTreeMap<NodeRewardType, u32>> =
        btreemap! {
            "q4gds-li2kf-dhmi6-vmtxg-zrgep-3te7r-2a4ji-nszwv-66biu-dkl6k-eqe" => btreemap! {"type3.1" => 1},
            "u7afs-z2fqh-zbqyo-jufwe-3vqqs-chc7f-k2fe4-rt66w-l4qia-keuuj-qqe" => btreemap! {"type3.1" => 1},
            "7v3fg-puvon-km4rh-gnvqw-pmlug-5iaen-s3v45-kwowl-etrtl-xc245-qqe" => btreemap! {"type3.1" => 1},
            "ilwyu-pfcy7-2iy3t-cjmsx-nrw4l-6rmek-lduaa-yha6b-7wck6-3usxt-cqe" => btreemap! {"type3.1" => 1},
            "tnqod-r52q6-ub547-756zx-7fokh-l5uga-23zbn-lll2x-ebe5r-fdgyh-oae" => btreemap! {"type3.1" => 1},
            "3pvkg-yll72-7bgau-ifrdj-5hfoz-qurfj-vvl2l-6ztjm-rdbg2-56al6-cqe" => btreemap! {"type3.1" => 1},
            "ziab5-kch42-6jhxt-26xf7-wej5v-xw4oh-36m5y-yba7v-xrtpv-pobv3-fqe" => btreemap! {"type3.1" => 1},
            "rsrz6-sc2oj-azljq-mxw7a-daryz-yxmzm-qyn67-6hls2-vnn5d-izzf5-pqe" => btreemap! {"type3.1" => 1},
            "yedtm-rm5av-s256v-zzi4w-7lxen-koqg6-pzak3-rjzko-xfu2c-dw7eo-bae" => btreemap! {"type3.1" => 1},
            "2mie5-aobqb-l2gvy-2or7x-di7cx-3xoij-ifiej-zqxlm-hzn6s-lp2ih-kqe" => btreemap! {"type3.1" => 1},
            "hsi7b-rl4wt-lum3m-ophfi-oxgx5-u2q7r-ak7ag-nyiik-c4gam-epo2r-3qe" => btreemap! {"type3.1" => 1},
            "nwpoe-kxdae-5afgc-itoe7-xecg7-k74et-jggwc-lgz3n-tjs6e-mtqos-5ae" => btreemap! {"type3.1" => 1},
            "a7uqi-wzcgk-bjijx-f562s-a2pm6-qriyn-qmvcw-jtzrw-nx64c-3ocff-iqe" => btreemap! {"type3.1" => 1},
        }
        .into_iter()
        .map(|(node_operator_id, max_rewardable_nodes)| {
            let node_operator_id_processed = PrincipalId::from_str(node_operator_id).unwrap();
            let max_rewardable_nodes_processed = max_rewardable_nodes
                .into_iter()
                .map(|(node_reward_type, count)| {
                    (
                        NodeRewardType::from(node_reward_type.to_string()),
                        count as u32,
                    )
                })
                .collect();

            (node_operator_id_processed, max_rewardable_nodes_processed)
        })
        .collect();
}
