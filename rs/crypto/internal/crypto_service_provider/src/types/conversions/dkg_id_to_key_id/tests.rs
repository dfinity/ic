use super::*;
use ic_crypto_internal_test_vectors::unhex::hex_to_32_bytes;
use ic_types::{Height, SubnetId};
use ic_types_test_utils::ids::subnet_test_id;

#[test]
fn should_map_equal_dkg_ids_to_the_same_key_id() {
    let dkg_id_1 = dkg_id_with_instance_and_subnet(1, subnet_test_id(2));
    let dkg_id_2 = dkg_id_with_instance_and_subnet(1, subnet_test_id(2));
    assert_eq!(dkg_id_1, dkg_id_2);

    let key_id_1 = dkg_id_to_key_id(&dkg_id_1);
    let key_id_2 = dkg_id_to_key_id(&dkg_id_2);

    assert_eq!(key_id_1, key_id_2);
}

#[test]
fn should_map_distinct_dkg_ids_to_distinct_key_ids() {
    let dkg_id_1 = dkg_id_with_instance_and_subnet(1, subnet_test_id(2));
    let dkg_id_2 = dkg_id_with_instance_and_subnet(3, subnet_test_id(4));
    assert_ne!(dkg_id_1, dkg_id_2);

    let key_id_1 = dkg_id_to_key_id(&dkg_id_1);
    let key_id_2 = dkg_id_to_key_id(&dkg_id_2);

    assert_ne!(key_id_1, key_id_2);
}

#[test]
fn should_not_map_dkg_ids_to_the_same_key_id_if_only_instance_differs() {
    let dkg_id_1 = dkg_id_with_instance_and_subnet(1, subnet_test_id(2));
    let dkg_id_2 = dkg_id_with_instance_and_subnet(3, subnet_test_id(2));
    assert_ne!(dkg_id_1, dkg_id_2);

    let key_id_1 = dkg_id_to_key_id(&dkg_id_1);
    let key_id_2 = dkg_id_to_key_id(&dkg_id_2);

    assert_ne!(key_id_1, key_id_2);
}

#[test]
fn should_not_map_dkg_ids_to_the_same_key_id_if_only_subnet_differs() {
    let dkg_id_1 = dkg_id_with_instance_and_subnet(1, subnet_test_id(2));
    let dkg_id_2 = dkg_id_with_instance_and_subnet(1, subnet_test_id(3));
    assert_ne!(dkg_id_1, dkg_id_2);

    let key_id_1 = dkg_id_to_key_id(&dkg_id_1);
    let key_id_2 = dkg_id_to_key_id(&dkg_id_2);

    assert_ne!(key_id_1, key_id_2);
}

// The mapping of `IDkgId` to KeyId must be injective.
//
// Since the hash code of the `IDkgId` is used to generate the KeyId, the KeyId
// may change if the implementation of `IDkgId` changes. This test fails in that
// case. Such a change should most probably be avoided, as this means that,
// e.g., keys that were stored for a given `IDkgId` will no longer be found in
// the store. Any solution to this problem should keep the properties of the
// injective mapping.
#[test]
fn should_not_change_key_id_due_to_dkg_id_implementation_changes() {
    let hard_coded_key_id = hard_coded_key_id_for_instance_1_and_subnet_2();
    let dkg_id = dkg_id_with_instance_and_subnet(1, subnet_test_id(2));

    let key_id = dkg_id_to_key_id(&dkg_id);

    assert_eq!(key_id, hard_coded_key_id);
}

fn hard_coded_key_id_for_instance_1_and_subnet_2() -> KeyId {
    KeyId::from(hex_to_32_bytes(
        "14ab5dba1e76a93f0014097319608cf76a88c16262d4f697704036a285f6f36d",
    ))
}

fn dkg_id_with_instance_and_subnet(instance_id: u64, subnet_id: SubnetId) -> IDkgId {
    IDkgId {
        instance_id: Height::from(instance_id),
        subnet_id,
    }
}
