use std::str::FromStr;

use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve, VetKdKeyId,
};
use ic_types::PrincipalId;

use super::*;

fn minimal_recover_payload(
    subnet_id: SubnetId,
    height: u64,
    time_ns: u64,
    state_hash: String,
) -> do_recover_subnet::RecoverSubnetPayload {
    do_recover_subnet::RecoverSubnetPayload {
        subnet_id: subnet_id.get(),
        height,
        time_ns,
        state_hash: hex::decode(state_hash)
            .unwrap_or_else(|err| panic!("Invalid state hash: {err}")),
        replacement_nodes: None,
        registry_store_uri: None,
        chain_key_config: None,
    }
}

fn empty_propose_to_recover_subnet_cmd(
    subnet_id: SubnetId,
    height: u64,
    time_ns: u64,
    state_hash: String,
) -> ProposeToUpdateRecoveryCupCmd {
    ProposeToUpdateRecoveryCupCmd {
        subnet: SubnetDescriptor::Id(subnet_id.get()),
        test_neuron_proposer: false,
        dry_run: false,
        json: true,
        height,
        time_ns,
        state_hash,
        replacement_nodes: None,
        proposer: None,
        proposal_url: None,
        proposal_title: None,
        summary: None,
        summary_file: None,
        registry_store_uri: None,
        registry_store_hash: None,
        registry_version: None,
        initial_chain_key_configs_to_request: None,
        signature_request_timeout_ns: None,
        idkg_key_rotation_period_ms: None,
        max_parallel_pre_signature_transcripts_in_creation: None,
    }
}

#[test]
fn cli_to_payload_conversion_works_for_chain_key_fields() {
    // Boilerplate stuff
    let subnet_id = SubnetId::from(PrincipalId::new_user_test_id(1));
    let height = 107428000;
    let time_ns = 1719241477392602354;
    let state_hash =
        "5d6601ac575f565b7c61d6bf5f9b25fa503bf7d756210a9a1fe8d8a32967f2e5".to_string();

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
    let cmd = ProposeToUpdateRecoveryCupCmd {
        initial_chain_key_configs_to_request,
        signature_request_timeout_ns,
        idkg_key_rotation_period_ms,
        max_parallel_pre_signature_transcripts_in_creation,
        ..empty_propose_to_recover_subnet_cmd(subnet_id, height, time_ns, state_hash.clone())
    };
    assert_eq!(
        cmd.new_payload_for_subnet(subnet_id),
        do_recover_subnet::RecoverSubnetPayload {
            chain_key_config: Some(do_recover_subnet::InitialChainKeyConfig {
                key_configs: vec![
                    do_recover_subnet::KeyConfigRequest {
                        key_config: Some(do_recover_subnet::KeyConfig {
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
                    do_recover_subnet::KeyConfigRequest {
                        key_config: Some(do_recover_subnet::KeyConfig {
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
                    do_recover_subnet::KeyConfigRequest {
                        key_config: Some(do_recover_subnet::KeyConfig {
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
            ..minimal_recover_payload(subnet_id, height, time_ns, state_hash)
        },
    );
}
