use super::*;
use crate::models::{CurveType, PublicKey};
use ic_types::time::Time;
use rand_chacha::rand_core::OsRng;
use rosetta_core::convert::principal_id_from_public_key;

const HOUR_NANOS: u64 = 60 * 60 * 1_000_000_000;
// A realistic "now" (~2023) that is well away from the u64 boundary.
const NOW_NANOS: u64 = 1_700_000_000 * 1_000_000_000;

fn t(nanos: u64) -> Time {
    Time::from_nanos_since_unix_epoch(nanos)
}

#[test]
fn every_neuron_payload_passes_signed_target_verification() {
    let ledger_canister_id = CanisterId::from_u64(0x1233);
    let governance_canister_id = CanisterId::from_u64(0x1234);

    let key = ic_ed25519::PrivateKey::generate_using_rng(&mut OsRng);
    let pub_key = PublicKey {
        hex_bytes: hex::encode(key.public_key().serialize_raw()),
        curve_type: CurveType::Edwards25519,
    };
    let account =
        icp_ledger::AccountIdentifier::from(principal_id_from_public_key(&pub_key).unwrap());
    let pks_map = HashMap::from([(account, &pub_key)]);
    let ingress_expiries = [1_u64];
    let neuron_index = 7;
    let other = PrincipalId::new_user_test_id(42);

    let mut updates = vec![];
    macro_rules! build {
        ($handle:ident, $req:expr) => {
            $handle(
                $req,
                &governance_canister_id,
                &mut vec![],
                &mut updates,
                &pks_map,
                &ingress_expiries,
            )
            .unwrap()
        };
    }

    build!(
        handle_stake,
        Stake {
            account,
            neuron_index
        }
    );
    for controller in [None, Some(other)] {
        build!(
            handle_neuron_info,
            NeuronInfo {
                account,
                controller,
                neuron_index,
            }
        );
    }
    for page_number in [None, Some(3)] {
        build!(
            handle_list_neurons,
            ListNeurons {
                account,
                page_number
            }
        );
    }
    build!(
        handle_set_dissolve_timestamp,
        SetDissolveTimestamp {
            account,
            neuron_index,
            timestamp: crate::models::seconds::Seconds(1_000),
        }
    );
    build!(
        handle_change_auto_stake_maturity,
        ChangeAutoStakeMaturity {
            account,
            neuron_index,
            requested_setting_for_auto_stake_maturity: true,
        }
    );
    build!(
        handle_start_dissolve,
        StartDissolve {
            account,
            neuron_index
        }
    );
    build!(
        handle_stop_dissolve,
        StopDissolve {
            account,
            neuron_index
        }
    );
    build!(
        handle_disburse,
        Disburse {
            account,
            amount: Some(Tokens::from_e8s(1)),
            recipient: Some(icp_ledger::AccountIdentifier::from(other)),
            neuron_index,
        }
    );
    build!(
        handle_disburse_maturity,
        DisburseMaturity {
            account,
            percentage_to_disburse: 100,
            recipient: None,
            neuron_index,
        }
    );
    build!(
        handle_add_hotkey,
        AddHotKey {
            account,
            neuron_index,
            key: PublicKeyOrPrincipal::Principal(other),
        }
    );
    build!(
        handle_remove_hotkey,
        RemoveHotKey {
            account,
            neuron_index,
            key: PublicKeyOrPrincipal::Principal(other),
        }
    );
    build!(
        handle_spawn,
        Spawn {
            account,
            spawned_neuron_index: neuron_index + 1,
            controller: Some(other),
            percentage_to_spawn: Some(50),
            neuron_index,
        }
    );
    build!(
        handle_stake_maturity,
        StakeMaturity {
            account,
            percentage_to_stake: Some(50),
            neuron_index,
        }
    );
    build!(
        handle_register_vote,
        RegisterVote {
            account,
            proposal: Some(1),
            vote: 1,
            neuron_index,
        }
    );
    for controller in [None, Some(other)] {
        build!(
            handle_follow,
            Follow {
                account,
                topic: 0,
                followees: vec![1],
                controller,
                neuron_index,
            }
        );
        build!(
            handle_refresh_voting_power,
            RefreshVotingPower {
                account,
                neuron_index,
                controller,
            }
        );
    }

    assert_eq!(updates.len(), 20);
    for (request_type, update) in &updates {
        crate::signed_target::verify_signed_target(
            request_type,
            update,
            &ledger_canister_id,
            &governance_canister_id,
        )
        .unwrap_or_else(|e| panic!("{request_type:?} was rejected: {e:?}"));
    }
}

#[test]
fn neuron_requests_are_addressed_to_the_configured_governance_canister() {
    let governance_canister_id = CanisterId::from_u64(0x1234);
    assert_ne!(
        governance_canister_id,
        ic_nns_constants::GOVERNANCE_CANISTER_ID
    );

    let key = ic_ed25519::PrivateKey::generate_using_rng(&mut OsRng);
    let pub_key = PublicKey {
        hex_bytes: hex::encode(key.public_key().serialize_raw()),
        curve_type: CurveType::Edwards25519,
    };
    let account =
        icp_ledger::AccountIdentifier::from(principal_id_from_public_key(&pub_key).unwrap());
    let pks_map = HashMap::from([(account, &pub_key)]);
    let ingress_expiries = [1_u64];

    let check = |what: &str, updates: Vec<(RequestType, HttpCanisterUpdate)>| {
        let (_, update) = updates
            .first()
            .unwrap_or_else(|| panic!("{what}: no update"));
        assert_eq!(
            update.canister_id.0.as_slice(),
            governance_canister_id.get().as_slice(),
            "{what} was not addressed to the configured governance canister",
        );
    };

    let mut payloads = vec![];
    let mut updates = vec![];
    handle_start_dissolve(
        StartDissolve {
            account,
            neuron_index: 0,
        },
        &governance_canister_id,
        &mut payloads,
        &mut updates,
        &pks_map,
        &ingress_expiries,
    )
    .unwrap();
    check("manage_neuron", updates);

    let mut payloads = vec![];
    let mut updates = vec![];
    handle_stake(
        Stake {
            account,
            neuron_index: 0,
        },
        &governance_canister_id,
        &mut payloads,
        &mut updates,
        &pks_map,
        &ingress_expiries,
    )
    .unwrap();
    check("stake", updates);

    let mut payloads = vec![];
    let mut updates = vec![];
    handle_neuron_info(
        NeuronInfo {
            account,
            controller: None,
            neuron_index: 0,
        },
        &governance_canister_id,
        &mut payloads,
        &mut updates,
        &pks_map,
        &ingress_expiries,
    )
    .unwrap();
    check("neuron_info", updates);

    let mut payloads = vec![];
    let mut updates = vec![];
    handle_list_neurons(
        ListNeurons {
            account,
            page_number: None,
        },
        &governance_canister_id,
        &mut payloads,
        &mut updates,
        &pks_map,
        &ingress_expiries,
    )
    .unwrap();
    check("list_neurons", updates);
}

// A window whose span exceeds the documented 24h bound would make the loop
// build a huge list of ingress expiries, so it is rejected before the loop.
#[test]
fn oversized_ingress_window_is_rejected() {
    assert!(
        validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS), t(NOW_NANOS + 48 * HOUR_NANOS))
            .is_err()
    );
}

// A near-zero start together with a near-`u64::MAX` end spans almost the
// entire u64 range; that enormous span is rejected (it would otherwise
// iterate billions of times).
#[test]
fn unbounded_ingress_span_is_rejected() {
    assert!(validate_ingress_window(t(NOW_NANOS), t(0), t(u64::MAX)).is_err());
}

// A window ending at (near) `u64::MAX` has a small span but an end far in the
// future; without the future bound the loop counter would wrap past
// `u64::MAX` and never terminate. The future bound rejects it.
#[test]
fn near_u64_max_ingress_window_is_rejected() {
    let start = t(u64::MAX - 50 * 1_000_000_000);
    assert!(validate_ingress_window(t(NOW_NANOS), start, t(u64::MAX)).is_err());
}

// A reversed or empty window (ingress_end <= ingress_start) is rejected
// rather than silently producing an empty set of payloads.
#[test]
fn reversed_ingress_window_is_rejected() {
    assert!(validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS + 1), t(NOW_NANOS)).is_err());
    assert!(validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS), t(NOW_NANOS)).is_err());
}

// Negative control: a realistic window (5 minutes ahead of now) is accepted.
#[test]
fn valid_ingress_window_is_accepted() {
    let end = t(NOW_NANOS + 5 * 60 * 1_000_000_000);
    assert!(validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS), end).is_ok());
}

// Boundary: a window of exactly 24h ending exactly 24h from now is accepted,
// one nanosecond more is rejected.
#[test]
fn ingress_window_boundary_is_inclusive() {
    let max = MAX_INGRESS_WINDOW.as_nanos() as u64;
    assert!(validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS), t(NOW_NANOS + max)).is_ok());
    assert!(validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS), t(NOW_NANOS + max + 1)).is_err());
}

// Boundary: exactly the maximum number of (request, ingress expiry) pairs is
// accepted, one more request or one more expiry is rejected.
#[test]
fn request_ingress_expiry_pairs_boundary_is_inclusive() {
    const EXPIRIES: usize = 720;
    const MAX_REQUESTS: usize = MAX_REQUEST_INGRESS_EXPIRY_PAIRS / EXPIRIES;
    assert_eq!(MAX_REQUESTS * EXPIRIES, MAX_REQUEST_INGRESS_EXPIRY_PAIRS);

    assert!(validate_request_ingress_expiry_pairs(MAX_REQUESTS - 1, EXPIRIES).is_ok());
    assert!(validate_request_ingress_expiry_pairs(MAX_REQUESTS, EXPIRIES).is_ok());
    assert!(validate_request_ingress_expiry_pairs(MAX_REQUESTS + 1, EXPIRIES).is_err());
    assert!(validate_request_ingress_expiry_pairs(MAX_REQUEST_INGRESS_EXPIRY_PAIRS, 1).is_ok());
    assert!(
        validate_request_ingress_expiry_pairs(MAX_REQUEST_INGRESS_EXPIRY_PAIRS + 1, 1).is_err()
    );
}

// The product of the counts must not wrap around and slip under the bound.
#[test]
fn request_ingress_expiry_pairs_overflow_is_rejected() {
    assert!(validate_request_ingress_expiry_pairs(usize::MAX, 2).is_err());
    assert!(validate_request_ingress_expiry_pairs(2, usize::MAX).is_err());
}
