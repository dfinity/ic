use crate::{
    models::{
        ConstructionHashRequest, ConstructionPayloadsRequest, NetworkIdentifier, SignedTransaction,
    },
    request_handler::{
        RosettaRequestHandler,
        tests::construction::{
            setup_handler, setup_transfer_test, sign_and_combine, signed_disburse,
        },
    },
    request_types::RequestType,
    transaction_id::NEURON_MANAGEMENT_PSEUDO_HASH,
};
use std::str::FromStr;

fn signed_transfer() -> (RosettaRequestHandler, NetworkIdentifier, String) {
    let (handler, network_identifier, operations, pub_key, key) = setup_transfer_test();
    let payloads = handler
        .construction_payloads(ConstructionPayloadsRequest {
            network_identifier: network_identifier.clone(),
            operations,
            metadata: None,
            public_keys: Some(vec![pub_key.clone()]),
        })
        .unwrap();
    let signed = sign_and_combine(&handler, &network_identifier, &pub_key, &key, payloads);
    (handler, network_identifier, signed)
}

#[test]
fn a_genuine_transfer_is_hashed() {
    let (handler, network_identifier, signed) = signed_transfer();
    let hash = handler
        .construction_hash(ConstructionHashRequest {
            network_identifier,
            signed_transaction: signed,
        })
        .expect("a genuine transfer must hash");
    assert_ne!(
        hash.transaction_identifier.hash, NEURON_MANAGEMENT_PSEUDO_HASH,
        "a transfer must not be reported with the neuron management hash"
    );
}

#[test]
fn a_transfer_relabelled_as_neuron_management_is_rejected() {
    let (handler, network_identifier, signed) = signed_transfer();
    let mut relabelled = SignedTransaction::from_str(&signed).unwrap();
    for (request_type, _) in relabelled.requests.iter_mut() {
        *request_type = RequestType::StartDissolve { neuron_index: 0 };
    }

    handler
        .construction_hash(ConstructionHashRequest {
            network_identifier,
            signed_transaction: relabelled.to_string(),
        })
        .expect_err("a relabelled transfer must not be hashed");
}

#[test]
fn divergent_envelopes_are_rejected() {
    let (handler, network_identifier, pub_key, key) = setup_handler();
    let (_, _, displayed) = signed_disburse(&handler, &network_identifier, &pub_key, &key, 0);
    let (_, _, hidden) = signed_disburse(&handler, &network_identifier, &pub_key, &key, 7);

    let displayed = SignedTransaction::from_str(&displayed).unwrap();
    let hidden = SignedTransaction::from_str(&hidden).unwrap();
    let spliced = SignedTransaction {
        requests: vec![(
            RequestType::Disburse { neuron_index: 0 },
            vec![
                displayed.requests[0].1[0].clone(),
                hidden.requests[0].1[0].clone(),
            ],
        )],
    };

    handler
        .construction_hash(ConstructionHashRequest {
            network_identifier,
            signed_transaction: spliced.to_string(),
        })
        .expect_err("envelopes that disagree must not be hashed");
}

#[test]
fn a_request_without_envelopes_is_rejected() {
    let (handler, network_identifier, _pub_key, _key) = setup_handler();
    let transaction = SignedTransaction {
        requests: vec![(RequestType::Send, vec![])],
    };

    handler
        .construction_hash(ConstructionHashRequest {
            network_identifier,
            signed_transaction: transaction.to_string(),
        })
        .expect_err("a request without envelopes has no hash");
}
