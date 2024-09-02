use ic_base_types::NumBytes;
use ic_canonical_state::lazy_tree_conversion::replicated_state_as_lazy_tree;
use ic_canonical_state_tree_hash::hash_tree::hash_lazy_tree;
use ic_canonical_state_tree_hash_test_utils::crypto_hash_lazy_tree;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_test_utilities_state::insert_dummy_canister;
use ic_test_utilities_types::ids::{
    canister_test_id, message_test_id, subnet_test_id, user_test_id,
};
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types::time::UNIX_EPOCH;

#[test]
fn simple_state_old_vs_new_hashing() {
    let state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&replicated_state_as_lazy_tree(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}

#[test]
fn many_canister_state_old_vs_new_hashing() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    for i in 1..1000 {
        insert_dummy_canister(&mut state, canister_test_id(i), user_test_id(24).get());
    }

    let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&replicated_state_as_lazy_tree(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}

#[test]
fn large_history_state_old_vs_new_hashing() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    for i in 1..1000 {
        state.set_ingress_status(
            message_test_id(i),
            IngressStatus::Known {
                receiver: canister_test_id(i).get(),
                user_id: user_test_id(i),
                time: UNIX_EPOCH,
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
        );
    }

    let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&replicated_state_as_lazy_tree(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}

#[test]
fn large_history_and_canisters_state_old_vs_new_hashing() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    for i in 1..1000 {
        insert_dummy_canister(&mut state, canister_test_id(i), user_test_id(24).get());

        state.set_ingress_status(
            message_test_id(i),
            IngressStatus::Known {
                receiver: canister_test_id(i).get(),
                user_id: user_test_id(i),
                time: UNIX_EPOCH,
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
        );
    }

    let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap();
    let crypto_hash_tree = crypto_hash_lazy_tree(&replicated_state_as_lazy_tree(&state));

    assert_eq!(hash_tree, crypto_hash_tree);
}

/// Guards against changes in `ic_error_types::RejectCode`. This will fail if
/// - A code is added, removed or changed
/// - The roundtrip to `u64` and back is changed
/// - The roundtrip to protobuf and back is changed
/// - A variant's name is changed
/// - The printer is changed, i.e. the result of `.to_string()` is changed.
#[test]
fn reject_code_change_guard() {
    use ic_crypto_sha2::Sha256;
    use ic_error_types::RejectCode;
    use std::hash::Hash;
    use strum::IntoEnumIterator;

    let mut hasher = Sha256::new();
    for variant in RejectCode::iter() {
        (
            variant,
            variant as u64,
            RejectCode::try_from(variant as u64).unwrap(),
            RejectCode::try_from(ic_protobuf::types::v1::RejectCode::from(variant)).unwrap(),
            format!("{variant:?}"),
            variant.to_string(),
        )
            .hash(&mut hasher);
    }

    // If this assert fails, you have made a potentially incompatible change to
    // `RejectCode`. This is problematic because `RejectCode` values are encoded into
    // the certified state tree and successive replica releases must have identical
    // representation of the certified state tree.
    //
    // Changes to `RejectCode` must be rolled out in stages, across multiple replica
    // releases. You must also ensure that a release is deployed to every subnet
    // before proceeding with the next stage of the release.
    //
    //  * If you are removing a `RejectCode` variant, in the first stage remove all
    //   uses of said variant from production code (except its definition and any
    //   conversion logic); only once this change has been deployed to all subnets,
    //   in the second phase, remove the variant and update this test.
    //
    //  * If you are adding a `RejectCode` variant, in the first stage define the
    //    variant and the necessary conversion logic, without using it anywhere (and
    //    update this test); once the replica release has been deployed to all
    //    subnets, it is safe to begin using the new variant in production code.
    //
    //  * Renaming a variant should be safe to do in one go, provided its numeric
    //    and `ToString` representations do not change. Just update this test.
    //
    //  * If you are remapping the numeric code behind a variant, you must do it as
    //    concurrent removal and addition operations (see above). You can also
    //    rename the variant you are removing to `Deprecated<Name>` as part of the
    //    first step, so you can concurrently define the new variant and preserve
    //    the name.
    assert_eq!(
        [
            62, 95, 239, 10, 9, 26, 135, 101, 93, 198, 15, 123, 76, 160, 97, 217, 51, 216, 73, 141,
            199, 167, 113, 136, 162, 143, 206, 234, 246, 179, 138, 81
        ],
        hasher.finish()
    );
}

/// Guards against changes in `ic_error_types::ErrorCode`. This will fail if
/// - A code is added, removed or changed
/// - The roundtrip to protobuf and back is changed
/// - The conversion to `RejectCode` is changed
/// - A variant's name is changed
/// - The printer is changed, i.e. the result of `.to_string()` is changed.
#[test]
fn error_code_change_guard() {
    use ic_crypto_sha2::Sha256;
    use ic_error_types::{ErrorCode, RejectCode};
    use std::hash::Hash;
    use strum::IntoEnumIterator;

    let mut hasher = Sha256::new();
    for variant in ErrorCode::iter() {
        (
            variant,
            variant as u64,
            ErrorCode::try_from(ic_protobuf::state::ingress::v1::ErrorCode::from(variant)).unwrap(),
            RejectCode::from(variant),
            format!("{variant:?}"),
            variant.to_string(),
        )
            .hash(&mut hasher);
    }

    // If this assert fails, you have made a potentially incompatible change to
    // `ErrorCode`. This is problematic because `ErrorCode` values are encoded into
    // the certified state tree and successive replica releases must have identical
    // representation of the certified state tree.
    //
    // Changes to `ErrorCode` must be rolled out in stages, across multiple replica
    // releases. You must also ensure that a release is deployed to every subnet
    // before proceeding with the next stage of the release.
    //
    //  * If you are removing an `ErrorCode` variant, in the first stage remove all
    //   uses of said variant from production code (except its definition and any
    //   conversion logic); only once this change has been deployed to all subnets,
    //   in the second phase, remove the variant and update this test.
    //
    //  * If you are adding an `ErrorCode` variant, in the first stage define the
    //    variant and the necessary conversion logic, without using it anywhere (and
    //    update this test); once the replica release has been deployed to all
    //    subnets, it is safe to begin using the new variant in production code.
    //
    //  * Renaming a variant should be safe to do in one go, provided its numeric
    //    and `ToString` representations do not change. Just update this test.
    //
    //  * If you are remapping the numeric code behind a variant, you must do it as
    //    concurrent removal and addition operations (see above). You can also
    //    rename the variant you are removing to `Deprecated<Name>` as part of the
    //    first step, so you can concurrently define the new variant and preserve
    //    the name.
    assert_eq!(
        [
            49, 160, 44, 253, 61, 181, 131, 134, 148, 115, 119, 247, 83, 108, 123, 1, 163, 212,
            137, 11, 99, 122, 199, 16, 89, 105, 87, 234, 200, 211, 76, 96
        ],
        hasher.finish()
    );
}
