use ic_base_types::CanisterId;
use proptest::{
    prop_assert, prop_assert_eq, proptest, strategy::Strategy, test_runner::TestCaseError,
};
use std::time::SystemTime;

use crate::{
    errors::ApiError,
    models::{
        ConstructionCombineRequest, ConstructionParseRequest, ConstructionParseResponse,
        ConstructionPayloadsRequest, ConstructionPayloadsRequestMetadata, CurveType, EnvelopePair,
        NetworkIdentifier, PublicKey, Signature, SignatureType, UnsignedTransaction,
    },
    request::Request,
    request_handler::{RosettaRequestHandler, tests::construction::setup_transfer_test},
    request_types::RequestType,
};
use candid::Encode;
use ic_nns_governance_api::{
    ManageNeuronCommandRequest, ManageNeuronRequest,
    manage_neuron::{self, NeuronIdOrSubaccount},
};
use ic_types::{
    PrincipalId,
    messages::{
        Blob, HttpCallContent, HttpCanisterUpdate, HttpReadStateContent, HttpRequestEnvelope,
    },
};
use rosetta_core::objects::ObjectMap;

/// Length of the vector in the args built by the tests below. It is encoded with this
/// length and then patched to `DECLARED_VEC_LEN`, which is far beyond the decoding quotas.
const ENCODED_VEC_LEN: u64 = 1_234_567;
const DECLARED_VEC_LEN: u64 = 100_000_000;

fn leb128(mut n: u64) -> Vec<u8> {
    let mut bytes = vec![];
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            bytes.push(byte);
            return bytes;
        }
        bytes.push(byte | 0x80);
    }
}

/// Replaces the length of the single `ENCODED_VEC_LEN`-element vector in `args` with
/// `DECLARED_VEC_LEN`.
fn with_declared_vec_len(args: Vec<u8>) -> Vec<u8> {
    let encoded = leb128(ENCODED_VEC_LEN);
    let positions: Vec<usize> = args
        .windows(encoded.len())
        .enumerate()
        .filter(|(_, window)| *window == encoded.as_slice())
        .map(|(pos, _)| pos)
        .collect();
    assert_eq!(positions.len(), 1, "the vec length must occur exactly once");
    let pos = positions[0];
    [
        &args[..pos],
        &leb128(DECLARED_VEC_LEN),
        &args[pos + encoded.len()..],
    ]
    .concat()
}

fn zero_sized_vec() -> Vec<()> {
    vec![(); ENCODED_VEC_LEN as usize]
}

fn set_dissolve_timestamp_command() -> Option<ManageNeuronCommandRequest> {
    Some(ManageNeuronCommandRequest::Configure(
        manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::SetDissolveTimestamp(
                manage_neuron::SetDissolveTimestamp {
                    dissolve_timestamp_seconds: 1,
                },
            )),
        },
    ))
}

/// `manage_neuron` args that exceed the decoding quotas in different ways.
fn manage_neuron_args_exceeding_decoding_quotas() -> Vec<(&'static str, Vec<u8>)> {
    #[derive(candid::CandidType)]
    struct ManageNeuronWithExtraField {
        id: Option<ic_nns_common::pb::v1::NeuronId>,
        neuron_id_or_subaccount: Option<NeuronIdOrSubaccount>,
        command: Option<ManageNeuronCommandRequest>,
        extra: Vec<()>,
    }
    // A `SetFollowing` command whose `topic_following` holds records without fields. They
    // decode as `FolloweesForTopic` with all fields `None`, and take no bytes on the wire.
    #[derive(candid::CandidType)]
    struct EmptyRecord {}
    #[derive(candid::CandidType)]
    struct SetFollowingWithEmptyRecords {
        topic_following: Option<Vec<EmptyRecord>>,
    }
    #[derive(candid::CandidType)]
    enum CommandWithEmptyRecords {
        SetFollowing(SetFollowingWithEmptyRecords),
    }
    #[derive(candid::CandidType)]
    struct ManageNeuronWithEmptyRecords {
        id: Option<ic_nns_common::pb::v1::NeuronId>,
        neuron_id_or_subaccount: Option<NeuronIdOrSubaccount>,
        command: Option<CommandWithEmptyRecords>,
    }
    #[derive(candid::CandidType)]
    struct ManageNeuronWithMismatchedId {
        id: Option<Vec<()>>,
        neuron_id_or_subaccount: Option<NeuronIdOrSubaccount>,
        command: Option<ManageNeuronCommandRequest>,
    }
    let manage_neuron = ManageNeuronRequest {
        id: None,
        neuron_id_or_subaccount: None,
        command: set_dissolve_timestamp_command(),
    };
    vec![
        (
            "trailing argument",
            Encode!(&manage_neuron, &zero_sized_vec()).unwrap(),
        ),
        (
            "extra record field",
            Encode!(&ManageNeuronWithExtraField {
                id: None,
                neuron_id_or_subaccount: None,
                command: set_dissolve_timestamp_command(),
                extra: zero_sized_vec(),
            })
            .unwrap(),
        ),
        (
            "mismatched opt field",
            Encode!(&ManageNeuronWithMismatchedId {
                id: Some(zero_sized_vec()),
                neuron_id_or_subaccount: None,
                command: set_dissolve_timestamp_command(),
            })
            .unwrap(),
        ),
        (
            "known vector of empty records",
            Encode!(&ManageNeuronWithEmptyRecords {
                id: None,
                neuron_id_or_subaccount: None,
                command: Some(CommandWithEmptyRecords::SetFollowing(
                    SetFollowingWithEmptyRecords {
                        topic_following: Some(
                            (0..ENCODED_VEC_LEN).map(|_| EmptyRecord {}).collect(),
                        ),
                    },
                )),
            })
            .unwrap(),
        ),
    ]
    .into_iter()
    .map(|(name, args)| (name, with_declared_vec_len(args)))
    .collect()
}

fn set_dissolve_timestamp_update(arg: Vec<u8>) -> HttpCanisterUpdate {
    HttpCanisterUpdate {
        canister_id: Blob(CanisterId::from_u64(1).get().to_vec()),
        method_name: "manage_neuron".to_string(),
        arg: Blob(arg),
        sender: Blob(PrincipalId::new_user_test_id(1).to_vec()),
        ingress_expiry: 1,
        nonce: None,
        sender_info: None,
    }
}

fn parse_unsigned_set_dissolve_timestamp(
    handler: &RosettaRequestHandler,
    network_identifier: &NetworkIdentifier,
    arg: Vec<u8>,
) -> Result<ConstructionParseResponse, ApiError> {
    let unsigned_transaction = UnsignedTransaction {
        updates: vec![(
            RequestType::SetDissolveTimestamp { neuron_index: 0 },
            set_dissolve_timestamp_update(arg),
        )],
        ingress_expiries: vec![1],
    };
    handler.construction_parse(ConstructionParseRequest {
        network_identifier: network_identifier.clone(),
        signed: false,
        transaction: unsigned_transaction.to_string(),
    })
}

fn submitted_set_dissolve_timestamp(
    handler: &RosettaRequestHandler,
    arg: Vec<u8>,
) -> Result<Request, ApiError> {
    let update = set_dissolve_timestamp_update(arg);
    let read_state = crate::convert::make_read_state_from_update(&update);
    let envelope_pair = EnvelopePair {
        update: HttpRequestEnvelope {
            content: HttpCallContent::Call { update },
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        },
        read_state: HttpRequestEnvelope {
            content: HttpReadStateContent::ReadState { read_state },
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        },
    };
    Request::from_signed_request(
        &(
            RequestType::SetDissolveTimestamp { neuron_index: 0 },
            vec![envelope_pair],
        ),
        handler.ledger.ledger_canister_id(),
        handler.ledger.governance_canister_id(),
    )
}

#[test]
fn test_parse_and_submit_reject_args_exceeding_decoding_quotas() {
    let (handler, network_identifier, _, _, _) = setup_transfer_test();
    for (name, args) in manage_neuron_args_exceeding_decoding_quotas() {
        let err =
            parse_unsigned_set_dissolve_timestamp(&handler, &network_identifier, args.clone())
                .unwrap_err();
        // The decoding quota is the binding one: it charges skipped values 50 times their
        // cost, so it runs out before the skipping quota.
        assert!(
            format!("{err:?}").contains("Decoding cost exceeds the limit"),
            "{name}: unexpected parse error: {err:?}"
        );

        let err = submitted_set_dissolve_timestamp(&handler, args).unwrap_err();
        assert!(
            format!("{err:?}").contains("Could not parse manage_neuron")
                && format!("{err:?}").contains("Decoding cost exceeds the limit"),
            "{name}: unexpected submit error: {err:?}"
        );
    }
}

#[test]
fn test_parse_and_submit_accept_args_with_short_unexpected_vec() {
    // Values the decoder has to skip are fine as long as they stay within the quota.
    let (handler, network_identifier, _, _, _) = setup_transfer_test();
    let args = Encode!(
        &ManageNeuronRequest {
            id: None,
            neuron_id_or_subaccount: None,
            command: set_dissolve_timestamp_command(),
        },
        &vec![(); 100]
    )
    .unwrap();

    let parsed =
        parse_unsigned_set_dissolve_timestamp(&handler, &network_identifier, args.clone()).unwrap();
    assert_eq!(parsed.operations.len(), 1);

    assert!(matches!(
        submitted_set_dissolve_timestamp(&handler, args).unwrap(),
        Request::SetDissolveTimestamp(_)
    ));
}

#[test]
fn test_largest_follow_arg_is_well_within_decoding_quota() {
    // FOLLOW is the largest argument built by `/construction/payloads`.
    let follow_arg = |num_followees: u64| {
        Encode!(&ManageNeuronRequest {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(vec![0xff; 32])),
            command: Some(ManageNeuronCommandRequest::Follow(manage_neuron::Follow {
                topic: i32::MAX,
                followees: (0..num_followees)
                    .map(|id| ic_nns_common::pb::v1::NeuronId { id: u64::MAX - id })
                    .collect(),
            })),
        })
        .unwrap()
    };
    let cost =
        |arg: &[u8]| crate::convert::canister_method_arg_decoding_cost::<ManageNeuronRequest>(arg);

    // Governance allows at most 15 followees per topic. Most of the cost is not the
    // followees but the Candid type table of `ManageNeuronRequest` (about 2 KB, charged at 4
    // units per byte), which includes the whole `MakeProposal` tree: 15 followees cost about
    // 8,600, of which about 8,200 is the type table. If a governance API change trips this
    // check, it is the type table that grew; compare its new size to the quota and raise
    // `CANISTER_METHOD_ARG_DECODING_QUOTA` if needed.
    let max_cost = cost(&follow_arg(15));
    assert!(
        max_cost * 3 < crate::convert::CANISTER_METHOD_ARG_DECODING_QUOTA,
        "decoding cost {max_cost} is too close to the quota"
    );
    // Far more followees than governance accepts still decode.
    cost(&follow_arg(100));
}

#[test]
fn test_payloads_parse_identity() {
    let (handler, network_identifier, operations, pub_key, key) = setup_transfer_test();

    let gen_opt_u64 = proptest::option::of(proptest::prelude::any::<u64>());
    const ONE_HOUR_NANOS: u64 = 60 * 60 * 1_000_000_000;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Could not get system time")
        .as_nanos() as u64;
    // `ingress_start` is kept within a realistic window around `now`: the
    // ingress window is now bounded to 24h, and this
    // also avoids overflowing `ingress_start + ingress_interval` below.
    let gen_ingress_start = proptest::option::of(now..(now + ONE_HOUR_NANOS));
    let gen_metadata = proptest::option::of(
        (gen_opt_u64.clone(), gen_ingress_start, gen_opt_u64).prop_flat_map(
            |(created_at_time, ingress_start, memo)| {
                proptest::option::of(1..ONE_HOUR_NANOS).prop_map(move |ingress_interval| {
                    let ingress_end = ingress_interval
                        .map(|ingress_interval| ingress_start.unwrap_or(now) + ingress_interval);
                    ConstructionPayloadsRequestMetadata {
                        created_at_time,
                        ingress_start,
                        ingress_end,
                        memo,
                    }
                })
            },
        ),
    );

    fn check_metadata(
        expected_metadata: Option<ConstructionPayloadsRequestMetadata>,
        actual_metadata: ObjectMap,
    ) -> std::result::Result<(), TestCaseError> {
        match expected_metadata {
            None => {
                // memo and created_at_time are always populated by construction_payloads
                // (memo defaults to 0, created_at_time to the current time)
                prop_assert!(
                    actual_metadata.contains_key("memo"),
                    "Metadata should always contain a memo"
                );
                prop_assert!(
                    actual_metadata.contains_key("created_at_time"),
                    "Metadata should always contain a created_at_time"
                );
            }
            Some(expected_metadata) => {
                let expected_metadata = serde_json::to_value(expected_metadata).unwrap();
                let expected_metadata = expected_metadata.as_object().unwrap();
                if let Some(memo) = expected_metadata.get("memo") {
                    prop_assert_eq!(Some(memo), actual_metadata.get("memo"));
                } else {
                    prop_assert!(
                        actual_metadata.contains_key("memo"),
                        "Metadata should always contain a memo"
                    );
                }
                if let Some(created_at_time) = expected_metadata.get("created_at_time") {
                    prop_assert_eq!(
                        Some(created_at_time),
                        actual_metadata.get("created_at_time")
                    );
                } else {
                    prop_assert!(
                        actual_metadata.contains_key("created_at_time"),
                        "Metadata should always contain a created_at_time"
                    );
                }
            }
        }
        Ok(())
    }

    // check parse unsigned transaction
    proptest!(|(metadata in gen_metadata.clone())| {
        let handler = handler.clone();
        let construction_payloads_result = handler.construction_payloads(ConstructionPayloadsRequest {
            network_identifier: network_identifier.clone(),
            operations: operations.clone(),
            metadata: metadata.clone().map(|m|m.try_into().unwrap()),
            public_keys: Some(vec![pub_key.clone()]),
        }).unwrap();
        let unsigned_transaction = construction_payloads_result.unsigned_transaction;

        // parse the unsigned transaction and check the result
        let parsed = handler.construction_parse(ConstructionParseRequest {
            network_identifier: network_identifier.clone(),
            signed: false,
            transaction: unsigned_transaction,
        }).unwrap();

        prop_assert_eq!(operations.clone(), parsed.operations);

        // metadata must always be present
        prop_assert!(parsed.metadata.is_some(), "Metadata should always be returned");

        check_metadata(metadata, parsed.metadata.unwrap()).unwrap()
    });

    // check parse signed transaction
    // signing is slow => use less test cases
    let conf = proptest::test_runner::Config {
        cases: 32,
        ..Default::default()
    };
    proptest!(conf, |(metadata in gen_metadata.clone())| {
        let construction_payloads_result = handler.construction_payloads(ConstructionPayloadsRequest {
            network_identifier: network_identifier.clone(),
            operations: operations.clone(),
            metadata: metadata.clone().map(|m|m.try_into().unwrap()),
            public_keys: Some(vec![pub_key.clone()]),
        }).unwrap();
        let unsigned_transaction = construction_payloads_result.unsigned_transaction;

        // create the signed transaction
        let mut signatures = vec![];
        for payload in construction_payloads_result.payloads {
            let bytes = hex::decode(payload.clone().hex_bytes).unwrap();
            let signature = key.sign_message(&bytes);
            let signature = Signature {
                signing_payload: payload,
                public_key: PublicKey::new(hex::encode(key.public_key().serialize_raw()), CurveType::Edwards25519),
                signature_type: SignatureType::Ed25519,
                hex_bytes: hex::encode(signature),
            };
            signatures.push(signature);
        }

        let signed_transaction = handler.construction_combine(ConstructionCombineRequest {
            network_identifier:network_identifier.clone(),
            unsigned_transaction,
            signatures,
        }).unwrap().signed_transaction;

        // parse the signed transaction and check the result
        let parsed = handler.construction_parse(ConstructionParseRequest {
            network_identifier:network_identifier.clone(),
            signed: true,
            transaction: signed_transaction,
        }).unwrap();

        prop_assert_eq!(operations.clone(), parsed.operations);

        // metadata must always be present
        prop_assert!(parsed.metadata.is_some(), "Metadata should always be returned");

        check_metadata(metadata, parsed.metadata.unwrap()).unwrap()
    });
}

// When the caller does not specify a memo, `construction_payloads` uses a
// deterministic memo of 0 instead of a random one. With the time-based
// inputs pinned, reconstructing
// the same transfer must therefore produce a byte-identical unsigned
// transaction every time -- and hence the same transaction hash -- so that
// the ledger's `created_at_time` based deduplication can catch a retried
// transfer. This test reconstructs the same transfer three times and checks
// both that the unsigned transactions are identical and that the embedded
// memo is 0.
#[test]
fn test_payloads_without_memo_is_deterministic() {
    let (handler, network_identifier, operations, pub_key, _key) = setup_transfer_test();

    // Pin all time-based inputs so that the only thing that could vary
    // across reconstructions is the (previously random) memo.
    const NANOS: u64 = 1_000_000_000;
    let created_at_time = 1_700_000_000 * NANOS;
    let metadata = ConstructionPayloadsRequestMetadata {
        memo: None,
        created_at_time: Some(created_at_time),
        ingress_start: Some(created_at_time),
        ingress_end: Some(created_at_time + 600 * NANOS),
    };

    let reconstruct = || {
        handler
            .construction_payloads(ConstructionPayloadsRequest {
                network_identifier: network_identifier.clone(),
                operations: operations.clone(),
                metadata: Some(metadata.clone().try_into().unwrap()),
                public_keys: Some(vec![pub_key.clone()]),
            })
            .unwrap()
            .unsigned_transaction
    };

    let unsigned_transactions: Vec<String> = (0..3).map(|_| reconstruct()).collect();

    // Reconstruction must be deterministic: identical bytes => identical
    // transaction hash, which is what lets the ledger deduplicate retries.
    assert!(
        unsigned_transactions
            .iter()
            .all(|tx| *tx == unsigned_transactions[0]),
        "expected identical unsigned transactions across reconstructions, got {unsigned_transactions:?}"
    );

    // And the memo embedded in the (memo-less) transfer must be 0.
    let parsed = handler
        .construction_parse(ConstructionParseRequest {
            network_identifier: network_identifier.clone(),
            signed: false,
            transaction: unsigned_transactions[0].clone(),
        })
        .unwrap();
    let memo = parsed
        .metadata
        .expect("metadata should always be returned")
        .get("memo")
        .expect("memo should always be present")
        .clone();
    assert_eq!(memo, serde_json::json!(0), "expected a memo of 0");
}
