use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve, VetKdKeyId,
};
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_types::PrincipalId;

use super::*;

fn make_empty_update_payload(subnet_id: SubnetId) -> do_update_subnet::UpdateSubnetPayload {
    do_update_subnet::UpdateSubnetPayload {
        subnet_id,
        set_gossip_config_to_default: false,
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        halt_at_cup_height: None,
        features: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
        chain_key_config: None,
        chain_key_signing_enable: None,
        chain_key_signing_disable: None,
    }
}

fn empty_propose_to_update_subnet_cmd(subnet_id: SubnetId) -> ProposeToUpdateSubnetCmd {
    ProposeToUpdateSubnetCmd {
        subnet: SubnetDescriptor::Id(subnet_id.get()),
        test_neuron_proposer: false,
        dry_run: true,
        json: true,
        proposer: None,
        proposal_url: None,
        proposal_title: None,
        summary: None,
        summary_file: None,
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        start_as_nns: None,
        is_halted: None,
        halt_at_cup_height: None,
        chain_key_configs_to_generate: None,
        chain_key_signing_enable: None,
        chain_key_signing_disable: None,
        signature_request_timeout_ns: None,
        idkg_key_rotation_period_ms: None,
        max_parallel_pre_signature_transcripts_in_creation: None,
        features: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
        max_number_of_canisters: None,
    }
}

#[test]
fn cli_to_payload_conversion_works_for_chain_key_fields_for_signing_subnet() {
    // Boilerplate stuff
    let subnet_id = SubnetId::from(PrincipalId::new_user_test_id(1));
    let subnet_record = SubnetRecord {
        chain_key_config: Some(ChainKeyConfig {
            key_configs: vec![
                KeyConfig {
                    key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                        curve: EcdsaCurve::Secp256k1,
                        name: "some_key_name_3".to_string(),
                    }),
                    pre_signatures_to_create_in_advance: 555,
                    max_queue_size: 444,
                },
                KeyConfig {
                    key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                        curve: EcdsaCurve::Secp256k1,
                        name: "some_key_name_4".to_string(),
                    }),
                    pre_signatures_to_create_in_advance: 999,
                    max_queue_size: 888,
                },
            ],
            signature_request_timeout_ns: Some(111_111),
            idkg_key_rotation_period_ms: Some(111),
            max_parallel_pre_signature_transcripts_in_creation: Some(1),
        }),
        ..Default::default()
    };

    // Fields under test
    let chain_key_configs_to_generate = r#"[{
            "key_id": "ecdsa:Secp256k1:some_key_name_1",
            "pre_signatures_to_create_in_advance": "99",
            "max_queue_size": "155"
        },
        {
            "key_id": "schnorr:Bip340Secp256k1:some_key_name_2",
            "pre_signatures_to_create_in_advance": "98",
            "max_queue_size": "154"
        },
        {
            "key_id": "vetkd:Bls12_381_G2:some_key_name_5",
            "pre_signatures_to_create_in_advance": "0",
            "max_queue_size": "154"
        }]"#
    .to_string();
    let chain_key_configs_to_generate = Some(chain_key_configs_to_generate);

    let chain_key_signing_enable = Some(vec!["ecdsa:Secp256k1:some_key_name_3".to_string()]);

    let chain_key_signing_disable = Some(vec!["ecdsa:Secp256k1:some_key_name_4".to_string()]);

    let signature_request_timeout_ns = Some(222_222);
    let idkg_key_rotation_period_ms = Some(222);
    let max_parallel_pre_signature_transcripts_in_creation = Some(2);

    // Run code under test
    let cmd = ProposeToUpdateSubnetCmd {
        chain_key_configs_to_generate,
        chain_key_signing_enable,
        chain_key_signing_disable,
        signature_request_timeout_ns,
        idkg_key_rotation_period_ms,
        max_parallel_pre_signature_transcripts_in_creation,
        ..empty_propose_to_update_subnet_cmd(subnet_id)
    };

    assert_eq!(
        cmd.new_payload_for_subnet(subnet_id, subnet_record),
        do_update_subnet::UpdateSubnetPayload {
            chain_key_config: Some(do_update_subnet::ChainKeyConfig {
                // Note the order is not important so long as it is deterministic. As a matter
                // of fact, the order is lexicographic, as the implementation uses `BTreeSet`.
                key_configs: vec![
                    // New config, now being added.
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "some_key_name_1".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(99),
                        max_queue_size: Some(155),
                    },
                    // Existed before, now being enabled.
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "some_key_name_3".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(555),
                        max_queue_size: Some(444),
                    },
                    // Note that `some_key_name_4` is still here, although it is being disabled.
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "some_key_name_4".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(999),
                        max_queue_size: Some(888),
                    },
                    // Another new config, now being added.
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::Schnorr(SchnorrKeyId {
                            algorithm: SchnorrAlgorithm::Bip340Secp256k1,
                            name: "some_key_name_2".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(98),
                        max_queue_size: Some(154),
                    },
                    // A VetKd config, now being added.
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::VetKd(VetKdKeyId {
                            curve: VetKdCurve::Bls12_381_G2,
                            name: "some_key_name_5".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(0),
                        max_queue_size: Some(154),
                    },
                ],
                signature_request_timeout_ns: Some(222_222),
                idkg_key_rotation_period_ms: Some(222),
                max_parallel_pre_signature_transcripts_in_creation: Some(2),
            }),
            chain_key_signing_enable: Some(vec![MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "some_key_name_3".to_string(),
            })]),
            chain_key_signing_disable: Some(vec![MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "some_key_name_4".to_string(),
            })]),
            ..make_empty_update_payload(subnet_id)
        },
    );
}

#[test]
fn cli_to_payload_conversion_works_for_chain_key_fields_for_non_signing_subnet() {
    // Boilerplate stuff
    let subnet_id = SubnetId::from(PrincipalId::new_user_test_id(1));
    let subnet_record = SubnetRecord {
        chain_key_config: None,
        ..Default::default()
    };

    // Fields under test
    let chain_key_configs_to_generate = r#"[{
            "key_id": "ecdsa:Secp256k1:some_key_name_1",
            "pre_signatures_to_create_in_advance": "99",
            "max_queue_size": "155"
        },
        {
            "key_id": "schnorr:Bip340Secp256k1:some_key_name_2",
            "pre_signatures_to_create_in_advance": "98",
            "max_queue_size": "154"
        },
        {
            "key_id": "vetkd:Bls12_381_G2:some_key_name_3",
            "pre_signatures_to_create_in_advance": "0",
            "max_queue_size": "154"
        }]"#
    .to_string();
    let chain_key_configs_to_generate = Some(chain_key_configs_to_generate);

    let signature_request_timeout_ns = Some(111);
    let idkg_key_rotation_period_ms = Some(222);
    let max_parallel_pre_signature_transcripts_in_creation = Some(333);

    // Run code under test
    let cmd = ProposeToUpdateSubnetCmd {
        chain_key_configs_to_generate,
        signature_request_timeout_ns,
        idkg_key_rotation_period_ms,
        max_parallel_pre_signature_transcripts_in_creation,
        ..empty_propose_to_update_subnet_cmd(subnet_id)
    };

    assert_eq!(
        cmd.new_payload_for_subnet(subnet_id, subnet_record),
        do_update_subnet::UpdateSubnetPayload {
            chain_key_config: Some(do_update_subnet::ChainKeyConfig {
                key_configs: vec![
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "some_key_name_1".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(99),
                        max_queue_size: Some(155),
                    },
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::Schnorr(SchnorrKeyId {
                            algorithm: SchnorrAlgorithm::Bip340Secp256k1,
                            name: "some_key_name_2".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(98),
                        max_queue_size: Some(154),
                    },
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::VetKd(VetKdKeyId {
                            curve: VetKdCurve::Bls12_381_G2,
                            name: "some_key_name_3".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(0),
                        max_queue_size: Some(154),
                    },
                ],
                signature_request_timeout_ns: Some(111),
                idkg_key_rotation_period_ms: Some(222),
                max_parallel_pre_signature_transcripts_in_creation: Some(333),
            }),
            ..make_empty_update_payload(subnet_id)
        },
    );
}

#[test]
fn cli_to_payload_conversion_works_for_editing_existing_chain_key_fields() {
    // Boilerplate stuff
    let subnet_id = SubnetId::from(PrincipalId::new_user_test_id(1));
    let subnet_record = SubnetRecord {
        chain_key_config: Some(ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "some_key_name_1".to_string(),
                }),
                pre_signatures_to_create_in_advance: 111_111,
                max_queue_size: 222_222,
            }],
            signature_request_timeout_ns: Some(777_777),
            idkg_key_rotation_period_ms: Some(888_888),
            max_parallel_pre_signature_transcripts_in_creation: Some(999_999),
        }),
        ..Default::default()
    };

    // Fields under test
    let chain_key_configs_to_generate = r#"[{
            "key_id": "ecdsa:Secp256k1:some_key_name_1",
            "pre_signatures_to_create_in_advance": "111",
            "max_queue_size": "222"
        },
        {
            "key_id": "schnorr:Bip340Secp256k1:some_key_name_2",
            "pre_signatures_to_create_in_advance": "333",
            "max_queue_size": "444"
        },
        {
            "key_id": "vetkd:Bls12_381_G2:some_key_name_3",
            "pre_signatures_to_create_in_advance": "0",
            "max_queue_size": "444"
        }]"#
    .to_string();
    let chain_key_configs_to_generate = Some(chain_key_configs_to_generate);

    let signature_request_timeout_ns = Some(777);
    let idkg_key_rotation_period_ms = Some(888);
    let max_parallel_pre_signature_transcripts_in_creation = Some(999);

    // Run code under test
    let cmd = ProposeToUpdateSubnetCmd {
        chain_key_configs_to_generate,
        signature_request_timeout_ns,
        idkg_key_rotation_period_ms,
        max_parallel_pre_signature_transcripts_in_creation,
        ..empty_propose_to_update_subnet_cmd(subnet_id)
    };

    assert_eq!(
        cmd.new_payload_for_subnet(subnet_id, subnet_record),
        do_update_subnet::UpdateSubnetPayload {
            chain_key_config: Some(do_update_subnet::ChainKeyConfig {
                key_configs: vec![
                    // Existed before, now being updated.
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "some_key_name_1".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(111),
                        max_queue_size: Some(222),
                    },
                    // New config, now being added.
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::Schnorr(SchnorrKeyId {
                            algorithm: SchnorrAlgorithm::Bip340Secp256k1,
                            name: "some_key_name_2".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(333),
                        max_queue_size: Some(444),
                    },
                    // New config, now being added.
                    do_update_subnet::KeyConfig {
                        key_id: Some(MasterPublicKeyId::VetKd(VetKdKeyId {
                            curve: VetKdCurve::Bls12_381_G2,
                            name: "some_key_name_3".to_string(),
                        })),
                        pre_signatures_to_create_in_advance: Some(0),
                        max_queue_size: Some(444),
                    },
                ],
                signature_request_timeout_ns: Some(777),
                idkg_key_rotation_period_ms: Some(888),
                max_parallel_pre_signature_transcripts_in_creation: Some(999),
            }),
            ..make_empty_update_payload(subnet_id)
        },
    );
}
