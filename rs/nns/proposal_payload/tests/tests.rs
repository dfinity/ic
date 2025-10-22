use candid::Nat;
use ic_nns_proposal_payload::{candid_to_generic, candid_to_json, GenericValue};
use maplit::btreemap;
use serde_json::{json, Value as JsonValue};

fn registry_candid() -> &'static str {
    r#"
type AddNodeOperatorPayload = record {
  ipv6 : opt text;
  node_operator_principal_id : opt principal;
  node_allowance : nat64;
  rewardable_nodes : vec record { text; nat32 };
  node_provider_principal_id : opt principal;
  dc_id : text;
  max_rewardable_nodes : opt vec record { text; nat32 };
};

type CreateSubnetPayload = record {
  unit_delay_millis : nat64;
  features : SubnetFeatures;
  max_ingress_bytes_per_message : nat64;
  dkg_dealings_per_block : nat64;
  max_block_payload_size : nat64;
  start_as_nns : bool;
  is_halted : bool;
  max_ingress_messages_per_block : nat64;
  max_number_of_canisters : nat64;
  chain_key_config : opt InitialChainKeyConfig;
  replica_version_id : text;
  dkg_interval_length : nat64;
  subnet_id_override : opt principal;
  ssh_backup_access : vec text;
  initial_notary_delay_millis : nat64;
  subnet_type : SubnetType;
  ssh_readonly_access : vec text;
  node_ids : vec principal;
  canister_cycles_cost_schedule: opt CanisterCyclesCostSchedule;
  ingress_bytes_per_block_soft_cap : nat64;
  gossip_max_artifact_streams_per_peer : nat32;
  gossip_max_chunk_size : nat32;
  gossip_max_chunk_wait_ms : nat32;
  gossip_max_duplicity : nat32;
  gossip_pfn_evaluation_period_ms : nat32;
  gossip_receive_check_cache_size : nat32;
  gossip_registry_poll_period_ms : nat32;
  gossip_retransmission_request_ms : nat32;
};

type SubnetType = variant { application; verified_application; system };

type SubnetFeatures = record {
  canister_sandboxing : bool;
  http_requests : bool;
  sev_enabled : opt bool;
};

type InitialChainKeyConfig = record {
  key_configs : vec KeyConfigRequest;
  signature_request_timeout_ns : opt nat64;
  idkg_key_rotation_period_ms : opt nat64;
  max_parallel_pre_signature_transcripts_in_creation : opt nat32;
};

type CanisterCyclesCostSchedule = variant {
  Normal;
  Free;
};

type KeyConfigRequest = record {
  key_config : opt KeyConfig;
  subnet_id : opt principal;
};

type KeyConfig = record {
  key_id : opt MasterPublicKeyId;
  pre_signatures_to_create_in_advance : opt nat32;
  max_queue_size : opt nat32;
};

type MasterPublicKeyId = variant { Schnorr : SchnorrKeyId; Ecdsa : EcdsaKeyId; VetKd : VetKdKeyId };

type SchnorrKeyId = record { algorithm : SchnorrAlgorithm; name : text };

type SchnorrAlgorithm = variant { ed25519; bip340secp256k1 };

type VetKdKeyId = record { curve: VetKdCurve; name: text };

type VetKdCurve = variant { bls12_381_g2 };

type EcdsaCurve = variant { secp256k1 };

type EcdsaKeyId = record { name : text; curve : EcdsaCurve };

type ChangeSubnetMembershipPayload = record {
  node_ids_add : vec principal;
  subnet_id : principal;
  node_ids_remove : vec principal;
};

service : () -> {
    add_node_operator : (AddNodeOperatorPayload) -> ();
    create_subnet : (CreateSubnetPayload) -> ();
    change_subnet_membership : (ChangeSubnetMembershipPayload) -> ();
};
"#
}

fn root_candid() -> &'static str {
    r#"
type AddCanisterRequest = record {
  arg : blob;
  initial_cycles : nat64;
  wasm_module : blob;
  name : text;
  memory_allocation : opt nat;
  compute_allocation : opt nat;
};

service : () -> {
    add_nns_canister : (AddCanisterRequest) -> ();
};
    "#
}

fn test_candid_to_json(
    candid_source: &str,
    method_name: &str,
    args_hex: &str,
    expected_json: JsonValue,
) {
    let args = hex::decode(args_hex).unwrap();
    let json_value = candid_to_json(candid_source, method_name, &args).unwrap();
    assert_eq!(json_value, expected_json);
}

fn test_candid_to_generic(
    candid_source: &str,
    method_name: &str,
    args_hex: &str,
    expected_generic: GenericValue,
) {
    let args = hex::decode(args_hex).unwrap();
    let generic = candid_to_generic(candid_source, method_name, &args).unwrap();
    assert_eq!(generic, expected_generic);
}

#[test]
fn test_candid_to_json_add_node_operator() {
    test_candid_to_json(registry_candid(), "add_node_operator", "4449444c066c07a795f3ad0401f6c78e8808028af3a2b108059bf499bd0878bbf187b70c03dddfde9b0d05dba7aaae0d716e716e036d046c02007101796e680100000001011de031f3ffc70b56c84f347322945633179878c2c305a4344fde0cc1f1021c000000000000000001011d891cf0a4238671059529f2f36abeed7f74a6fe304f831acb4731289902036a7631",
        json!({
            "dc_id": "jv1",
            "ipv6": [],
            "max_rewardable_nodes": [],
            "node_allowance": 28,
            "node_operator_principal_id": ["mwn4q-m7agh-z77ry-lk3ee-6ndte-kkfmm-yxtb4-mfqyf-uq2e7-xqmyh-yqe"],
            "node_provider_principal_id": ["2hl5k-umjdt-ykii4-goecz-kkps6-nvl53-l7ost-p4mcp-qmnmw-rzrfc-mqe"],
            "rewardable_nodes": ""
        })
    );
}

#[test]
fn test_candid_to_json_create_subnet() {
    test_candid_to_json(registry_candid(), "create_subnet", "4449444c196c1c9dbcd60578fdd9dd96010196a9f88c0379eca0b7990478c884a9ac0478bfb798f10478a3c18e8d057ed5b6eede057e98b19cef0579fda7ecba07789f9c92970878afe0a79b0803f2adeaeb0879c9ef8ec50971bc94f9d10979b3d8ce8d0b79e1a296970b78ce8dd4cc0b05cac2d5e70c06afccbaf50c78d1f8fcb50d78e0cc8ebe0d07deedb4e40d799ced879c0e178a94d1cb0e06ee8389ea0e79e1b89fea0e79bbf8fded0f186c03d3aabef6027e9be288ed097ea6fbeca30b026e7e6e046b02cc91eff4027fc7ccf7a7067f6e686d716e086c03bae9eafd0a0991db92c30b0acbefc1e10c096e786d0b6c02bd869d8b0405a2c1ffbb0d0c6e0d6c03eabcee96030ebbebadff030fafdfe6c50e0e6e796e106b03f9c782dc0311beeec2bc0c13b4d889e30f156c02efd8baa70112cbe4fdc704716b02bbc38687057f949686ba0d7f6c02cbe4fdc70471af99e1f204146b01f3979dc30a7f6c02cbe4fdc70471af99e1f204166b019adee4ea017f6b03d0d6fad1027fd99abaea027fefad8a970f7f6d680100e80300000000000000010000000000000020000000000001000000000000000000400000000000000000000000e803000000000000000000000000000001010000000028653931356566656363386166393039393363636663343939373231656265383236616164626136300000000000000000f301000000000000000000000000000000002c010000000000000000000000000000000000000000000d011d03393f1bbb45acded952e5c8db59855a868eddbea59cd351078b4fe902011d0ccfd5184f3924decbf7c49d9443108bef40d09ad7194b272c33707902011d28c410cf79dd4c72df509701b09d85bfceaeda8e07296e768cb13fad02011d34281365d59f55b240d29b70677dc28613bb693ade72185dc49b52db02011d65187f47d4f45d5bc67147ce2fd3437906c22e5d18b5e9be6e54ca8302011d705b36c45aff18685ba7fc77399a8ee76e4ab7965420cee29a4288f802011d8a24175dc9aa5e3d836d926ccb8e3d555b5854d230eb236da3fbbf6502011d9d18fb0724c41360d41bf471e0d1e6bda0d46be0c6095065c7cb3ed202011da098810ae2227106688c7552a510ecbad5fbd8a48885f59bc240b09702011daf12ac2c4eeeb5711636617d35a14db5141018a3b6925d6d465c33e402011dc5620ca97c6674449bcf13a8a1d17f0001e39d3377affd0a9476f2d402011de39da4d9f276eae98f04d1541a0cc9cc368fc34b1f7ac9781668f30b02011dec129edb225e9e4ecde993880e2a487694ec9e4fe26516693800cbaa02",
        json!({
            "canister_cycles_cost_schedule": [{"Normal": null}],
            "chain_key_config": [],
            "dkg_dealings_per_block": 1,
            "dkg_interval_length": 499,
            "features": {
                "canister_sandboxing": false,
                "http_requests": true,
                "sev_enabled": []
            },
            "gossip_max_artifact_streams_per_peer": 0,
            "gossip_max_chunk_size": 0,
            "gossip_max_chunk_wait_ms": 0,
            "gossip_max_duplicity": 0,
            "gossip_pfn_evaluation_period_ms": 0,
            "gossip_receive_check_cache_size": 0,
            "gossip_registry_poll_period_ms": 0,
            "gossip_retransmission_request_ms": 0,
            "ingress_bytes_per_block_soft_cap": 0,
            "initial_notary_delay_millis": 300,
            "is_halted": false,
            "max_block_payload_size": 4194304,
            "max_ingress_bytes_per_message": 2097152,
            "max_ingress_messages_per_block": 1000,
            "max_number_of_canisters": 0,
            "node_ids": [
                "6souc-qqdhe-7rxo2-fvtpn-suxfz-dnvtb-k2q2h-n3pvf-ttjvc-b4lj7-uqe",
                "7r64j-zqmz7-krqtz-zetpm-x56et-wkege-el55a-nbgwx-dffso-lbtob-4qe",
                "kq3sv-bziyq-im66o-5jrzn-6uexa-gyj3b-n7z2x-nvdqh-ffxhn-dfrh6-wqe",
                "4g6xd-mzufa-jwlvm-7kwze-buu3o-btx3q-ugco5-wsow6-oimf3-re3kl-nqe",
                "n2h7o-alfdb-7upvh-ulvn4-m4khz-yx5gq-3za3b-c4xiy-wxu34-3suzk-bqe",
                "nsphz-ldqlm-3miwx-7dbuf-xj74o-44zvd-xhnzf-lpfsu-edhof-gscrd-4ae",
                "chcww-h4keq-lv3sn-kly6y-g3msn-tfy4p-kvlnm-fjurq-5mrw3-i73x5-sqe",
                "5nkgj-r45dd-5qojg-ecnqn-ig7uo-hqndz-v5udk-gxygg-bfigl-r6lh3-jae",
                "ub4s4-wfatc-aqvyr-coedg-rddvk-ksrb3-f22x5-5rjei-qx2zx-qsawc-lqe",
                "xqhoe-c5pck-wcytx-owvyr-mntbp-u22ct-nvcqi-bri5w-sjow2-rs4gp-sae",
                "qgbme-g6fmi-gks7d-gorcj-xtytv-cq5c7-yaahr-z2m3x-v76qv-fdw6l-kae",
                "jkyha-q7dtw-snt4t-w5luy-6bgrk-qnazs-omg2h-4gsy7-plexq-fti6m-fqe",
                "46dt2-4xmck-pnwis-6tzhm-32mtr-ahcus-dwstw-j4t7c-mulgs-oaazo-vae"
            ],
            "replica_version_id": "e915efecc8af90993ccfc499721ebe826aadba60",
            "ssh_backup_access": "",
            "ssh_readonly_access": "",
            "start_as_nns": false,
            "subnet_id_override": [],
            "subnet_type": {"application": null},
            "unit_delay_millis": 1000
        })
    );
}

#[test]
fn test_candid_to_json_change_subnet_membership() {
    test_candid_to_json(registry_candid(), "change_subnet_membership", "4449444c026c03ddd99b870301bd869d8b046888fe9fc80d016d68010002011d8f7efd3f5441fbc543c70974b39750ed54bc2a3a973625e6ed00753102011d2b80bae345b223d64ae23f41b26cb884689a38682f54787bf0544bd702011d6a8f67d86ecc8307048038ad71599458c131b531dc9bb0b691940db90202011d151768f1382be93caaed7e05ddc28bb12981f9f5a6136bfd4fd9f8ed02011dc916a302de3f7a3febed241e0ade3ebe350890811fa4419e237dabc902",
    json!({
        "node_ids_add":[
            "o4dpm-sepp3-6t6vc-b7pcu-hryjo-szzou-hnks6-cuoux-gys6n-3iaou-yqe",
            "hcvph-gzlqc-5ogrn-seple-vyr7i-gzgzo-eencn-dq2bp-kr4hx-4cujp-lqe"
        ],
        "node_ids_remove":[
            "2a7fq-jivc5-upcob-l5e6k-v3l6a-xo4fc-5rfga-7t5ng-cnv72-t6z7d-wqe",
            "shg6y-mwjc2-rqfxr-7pi76-x3jed-yfn4p-v6gue-jbai7-uraz4-i35vp-eqe"
        ],
        "subnet_id": "shefu-t3kr5-t5q3w-mqmdq-jabyv-vyvtf-cyyey-3kmo4-toyln-emubw-4qe"
    })
    );
}

#[test]
fn test_candid_to_json_add_nns_canister() {
    let arg = "7".repeat(2000);
    let wasm_module = "f".repeat(4000);
    let arg_hex = format!("4449444c036c06d6fca70201a8ddc06378a79fc97e01cbe4fdc70471deebb5a90e02a882acc60f026d7b6e7d0100e80{arg}715cd5b0700000000d00{wasm_module}f0c6e6f64655f726577617264730000");
    test_candid_to_json(
        root_candid(),
        "add_nns_canister",
        &arg_hex,
        json!({
            "arg": "[77777777...77777777](len:1000;sha256:04ffd92aef8aafe6f4f8388bc9f7c5b0d39eae37128b1ca693647b8569f8e629)",
            "initial_cycles": 123456789,
            "wasm_module": "[ffffffff...ffffffff](len:2000;sha256:19813270963599ad8ba084792ca1c8fcae3bc421aee518e709642df647fba6fe)",
            "name": "node_rewards",
            "memory_allocation": [],
            "compute_allocation": []
        }),
    );
}

#[test]
fn test_candid_to_generic_add_node_operator() {
    test_candid_to_generic(registry_candid(), "add_node_operator", "4449444c066c07a795f3ad0401f6c78e8808028af3a2b108059bf499bd0878bbf187b70c03dddfde9b0d05dba7aaae0d716e716e036d046c02007101796e680100000001011de031f3ffc70b56c84f347322945633179878c2c305a4344fde0cc1f1021c000000000000000001011d891cf0a4238671059529f2f36abeed7f74a6fe304f831acb4731289902036a7631",
        GenericValue::Map(
            btreemap! {
                "dc_id".to_string() => GenericValue::Text("jv1".to_string()),
                "ipv6".to_string() => GenericValue::Array(vec![]),
                "max_rewardable_nodes".to_string() => GenericValue::Array(vec![]),
                "node_allowance".to_string() => GenericValue::Nat(Nat::from(28u64)),
                "node_operator_principal_id".to_string() => GenericValue::Array(vec![
                    GenericValue::Text("mwn4q-m7agh-z77ry-lk3ee-6ndte-kkfmm-yxtb4-mfqyf-uq2e7-xqmyh-yqe".to_string())
                ]),
                "node_provider_principal_id".to_string() => GenericValue::Array(vec![
                    GenericValue::Text("2hl5k-umjdt-ykii4-goecz-kkps6-nvl53-l7ost-p4mcp-qmnmw-rzrfc-mqe".to_string())
                ]),
                "rewardable_nodes".to_string() => GenericValue::Text("".to_string()),
            }
        )
    );
}
