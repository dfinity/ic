use std::str::FromStr;

use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve, VetKdKeyId,
};
use ic_types::PrincipalId;

use super::*;

fn minimal_create_payload() -> do_create_subnet::CreateSubnetPayload {
    do_create_subnet::CreateSubnetPayload {
        canister_cycles_cost_schedule: Some(
            do_create_subnet::CanisterCyclesCostSchedule::Normal,
        ),
        ..Default::default()
    }
}

fn empty_propose_to_create_subnet_cmd() -> ProposeToCreateSubnetCmd {
    ProposeToCreateSubnetCmd {
        subnet_type: SubnetType::Application,
        test_neuron_proposer: false,
        dry_run: false,
        json: true,
        start_as_nns: false,
        is_halted: false,
        node_ids: vec![],
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
        proposer: None,
        proposal_url: None,
        proposal_title: None,
        summary: None,
        summary_file: None,
        subnet_handler_id: None,
        subnet_id_override: None,
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        replica_version_id: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        initial_chain_key_configs_to_request: None,
        signature_request_timeout_ns: None,
        idkg_key_rotation_period_ms: None,
        max_parallel_pre_signature_transcripts_in_creation: None,
        max_number_of_canisters: None,
        features: None,
    }
}

#[test]
fn cli_to_payload_conversion_works_for_chain_key_fields() {
    // Boilerplate stuff
    let replica_version_id = ReplicaVersion::default();
    let features = SubnetFeatures::default();

    let initial_chain_key_configs_to_request = r#"[{
            "key_id": "ecdsa:Secp256k1:some_key_name_1",
            "pre_signatures_to_create_in_advance": "99",
            "max_queue_size": "155",
            "subnet_id": "gxevo-lhkam-aaaaa-aaaap-yai"
        },
        {
            "key_id": "schnorr:Bip340Secp256k1:some_key_name_2",
            "pre_signatures_to_create_in_advance": "98",
            "max_queue_size": "154",
            "subnet_id": "gxevo-lhkam-aaaaa-aaaap-yai"
        },
        {
            "key_id": "vetkd:Bls12_381_G2:some_key_name_3",
            "pre_signatures_to_create_in_advance": "0",
            "max_queue_size": "154",
            "subnet_id": "gxevo-lhkam-aaaaa-aaaap-yai"
        }]"#
    .to_string();
    let initial_chain_key_configs_to_request = Some(initial_chain_key_configs_to_request);
    let signature_request_timeout_ns = Some(111);
    let idkg_key_rotation_period_ms = Some(222);
    let max_parallel_pre_signature_transcripts_in_creation = Some(333);

    // Run code under test
    let cmd = ProposeToCreateSubnetCmd {
        initial_chain_key_configs_to_request,
        signature_request_timeout_ns,
        idkg_key_rotation_period_ms,
        max_parallel_pre_signature_transcripts_in_creation,

        replica_version_id: Some(replica_version_id.clone()),
        features: Some(features),
        ..empty_propose_to_create_subnet_cmd()
    };
    assert_eq!(
        cmd.new_payload(),
        do_create_subnet::CreateSubnetPayload {
            chain_key_config: Some(do_create_subnet::InitialChainKeyConfig {
                key_configs: vec![
                    do_create_subnet::KeyConfigRequest {
                        key_config: Some(do_create_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                                curve: EcdsaCurve::Secp256k1,
                                name: "some_key_name_1".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(99),
                            max_queue_size: Some(155),
                        }),
                        subnet_id: Some(
                            PrincipalId::from_str("gxevo-lhkam-aaaaa-aaaap-yai").unwrap()
                        ),
                    },
                    do_create_subnet::KeyConfigRequest {
                        key_config: Some(do_create_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::Schnorr(SchnorrKeyId {
                                algorithm: SchnorrAlgorithm::Bip340Secp256k1,
                                name: "some_key_name_2".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(98),
                            max_queue_size: Some(154),
                        }),
                        subnet_id: Some(
                            PrincipalId::from_str("gxevo-lhkam-aaaaa-aaaap-yai").unwrap()
                        ),
                    },
                    do_create_subnet::KeyConfigRequest {
                        key_config: Some(do_create_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::VetKd(VetKdKeyId {
                                curve: VetKdCurve::Bls12_381_G2,
                                name: "some_key_name_3".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(0),
                            max_queue_size: Some(154),
                        }),
                        subnet_id: Some(
                            PrincipalId::from_str("gxevo-lhkam-aaaaa-aaaap-yai").unwrap()
                        ),
                    },
                ],
                signature_request_timeout_ns: Some(111),
                idkg_key_rotation_period_ms: Some(222),
                max_parallel_pre_signature_transcripts_in_creation: Some(333),
            }),
            replica_version_id: replica_version_id.to_string(),
            features: SubnetFeaturesPb::from(features),
            ..minimal_create_payload()
        },
    );
}
