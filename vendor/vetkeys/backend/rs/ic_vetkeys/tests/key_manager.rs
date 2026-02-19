use std::collections::BTreeSet;

use assert_matches::assert_matches;
use ic_cdk::management_canister::{VetKDCurve, VetKDKeyId};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager},
    DefaultMemoryImpl,
};
use ic_vetkeys::key_manager::KeyManager;
use ic_vetkeys::types::AccessRights;
use ic_vetkeys_test_utils::{
    random_access_rights, random_name, random_self_authenticating_principal,
    random_unique_memory_ids, random_utf8_string, reproducible_rng,
};
use rand::{CryptoRng, Rng};

#[test]
fn can_init_memory() {
    // prevent the compiler from optimizing away the function call
    std::hint::black_box(random_key_manager(&mut reproducible_rng()));
}

#[test]
fn get_accessible_shared_key_ids_works_correctly() {
    let rng = &mut reproducible_rng();
    let user_to_be_added = random_self_authenticating_principal(rng);
    let mut key_manager = random_key_manager(rng);

    let mut map_ids = BTreeSet::new();

    for _ in 0..10 {
        let caller = random_self_authenticating_principal(rng);
        let access_rights = random_access_rights(rng);
        let name = random_name(rng);

        assert_eq!(
            key_manager.set_user_rights(caller, (caller, name), user_to_be_added, access_rights),
            Ok(None)
        );

        map_ids.insert((caller, name));
        let computed_map_ids: BTreeSet<_> = key_manager
            .get_accessible_shared_key_ids(user_to_be_added)
            .into_iter()
            .collect();

        assert_eq!(computed_map_ids, map_ids);
    }
}

#[test]
fn can_get_shared_user_access_for_key() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut key_manager = random_key_manager(rng);

    let mut shared_access = BTreeSet::new();

    for _ in 0..10 {
        let user_to_be_added = random_self_authenticating_principal(rng);
        let access_rights = random_access_rights(rng);

        let computed_shared_access: BTreeSet<_> = key_manager
            .get_shared_user_access_for_key(caller, (caller, name))
            .unwrap()
            .into_iter()
            .collect();

        assert_eq!(shared_access, computed_shared_access);

        assert_eq!(
            key_manager.set_user_rights(caller, (caller, name), user_to_be_added, access_rights),
            Ok(None)
        );

        shared_access.insert((user_to_be_added, access_rights));
    }
}

#[test]
fn get_shared_user_access_for_key_fails_for_unauthorized() {
    let rng = &mut reproducible_rng();
    let unauthorized = random_self_authenticating_principal(rng);
    let key_id = (random_self_authenticating_principal(rng), random_name(rng));
    let key_manager = random_key_manager(rng);
    assert_eq!(
        key_manager.get_shared_user_access_for_key(unauthorized, key_id),
        Err("unauthorized".to_string())
    );
}

#[test]
fn can_add_user_to_key() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);

    let mut key_manager = random_key_manager(rng);

    let user_to_be_added = random_self_authenticating_principal(rng);
    let access_rights = random_access_rights(rng);

    assert_eq!(
        key_manager.get_user_rights(caller, (caller, name), user_to_be_added),
        Ok(None)
    );

    assert_eq!(
        key_manager.set_user_rights(caller, (caller, name), user_to_be_added, access_rights),
        Ok(None)
    );

    assert_eq!(
        key_manager.get_user_rights(caller, (caller, name), user_to_be_added),
        Ok(Some(access_rights))
    );

    assert_eq!(
        key_manager.set_user_rights(caller, (caller, name), user_to_be_added, access_rights),
        Ok(Some(access_rights))
    );
}

#[test]
fn get_and_set_user_rights_fails_for_unauthorized() {
    let rng = &mut reproducible_rng();
    let unauthorized = random_self_authenticating_principal(rng);
    let key_id = (random_self_authenticating_principal(rng), random_name(rng));
    let mut key_manager = random_key_manager(rng);
    assert_eq!(
        key_manager.get_user_rights(unauthorized, key_id, unauthorized),
        Err("unauthorized".to_string())
    );
    assert_eq!(
        key_manager.set_user_rights(unauthorized, key_id, unauthorized, AccessRights::Read),
        Err("unauthorized".to_string())
    );
}

#[test]
fn cannot_alter_owner_rights() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut key_manager = random_key_manager(rng);

    assert_eq!(
        key_manager.set_user_rights(caller, (caller, name), caller, AccessRights::Read),
        Err("cannot change key owner's user rights".to_string())
    );

    assert_eq!(
        key_manager.remove_user(caller, (caller, name), caller),
        Err("cannot remove key owner".to_string())
    );
}

#[test]
fn other_user_can_manage_key() {
    let rng = &mut reproducible_rng();
    let owner = random_self_authenticating_principal(rng);
    let user1 = random_self_authenticating_principal(rng);
    let user2 = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut key_manager = random_key_manager(rng);

    let key_id = (owner, name);

    key_manager
        .set_user_rights(owner, key_id, user1, AccessRights::ReadWriteManage)
        .unwrap();
    key_manager
        .set_user_rights(owner, key_id, user2, AccessRights::ReadWriteManage)
        .unwrap();

    key_manager.remove_user(user2, key_id, user1).unwrap();
    key_manager.remove_user(user2, key_id, user2).unwrap();
}

#[test]
fn can_remove_user_from_key() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut key_manager = random_key_manager(rng);

    let user_to_be_added = random_self_authenticating_principal(rng);
    let access_rights = random_access_rights(rng);
    assert_eq!(
        key_manager.set_user_rights(caller, (caller, name), user_to_be_added, access_rights,),
        Ok(None)
    );
    assert_eq!(
        key_manager.remove_user(caller, (caller, name), user_to_be_added,),
        Ok(Some(access_rights))
    );
    assert_eq!(
        key_manager.get_user_rights(caller, (caller, name), user_to_be_added),
        Ok(None)
    );
}

#[test]
fn add_or_remove_user_by_unauthorized_fails() {
    let rng = &mut reproducible_rng();
    let caller = random_self_authenticating_principal(rng);
    let name = random_name(rng);
    let mut key_manager = random_key_manager(rng);

    let mut unauthorized_callers = vec![random_self_authenticating_principal(rng)];

    for access_rights in [AccessRights::Read, AccessRights::ReadWrite] {
        let user_to_be_added = random_self_authenticating_principal(rng);

        assert_matches!(
            key_manager.set_user_rights(caller, (caller, name), user_to_be_added, access_rights,),
            Ok(_)
        );

        unauthorized_callers.push(user_to_be_added);
    }

    for unauthorized_caller in unauthorized_callers {
        for target in [random_self_authenticating_principal(rng), caller] {
            assert_eq!(
                key_manager.remove_user(unauthorized_caller, (caller, name), target),
                Err("unauthorized".to_string())
            );
            assert_eq!(
                key_manager.set_user_rights(
                    unauthorized_caller,
                    (caller, name),
                    target,
                    AccessRights::Read,
                ),
                Err("unauthorized".to_string())
            );
        }
    }
}

#[test]
fn can_instantiate_two_key_managers() {
    let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
    let key_manager_1 = KeyManager::<AccessRights>::init(
        "key_manager_1",
        bls12_381_dfx_test_key(),
        memory_manager.get(MemoryId::new(0)),
        memory_manager.get(MemoryId::new(1)),
        memory_manager.get(MemoryId::new(2)),
    );
    let key_manager_2 = KeyManager::<AccessRights>::init(
        "key_manager_2",
        bls12_381_dfx_test_key(),
        memory_manager.get(MemoryId::new(3)),
        memory_manager.get(MemoryId::new(4)),
        memory_manager.get(MemoryId::new(5)),
    );
    // prevent the compiler from optimizing away the function call
    std::hint::black_box((key_manager_1, key_manager_2));
}

fn random_key_manager<R: Rng + CryptoRng>(rng: &mut R) -> KeyManager<AccessRights> {
    let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
    let (_memory_id_encrypted_maps, memory_ids_key_manager) = random_unique_memory_ids(rng);
    let domain_separator_len = rng.gen_range(0..32);
    KeyManager::<AccessRights>::init(
        &random_utf8_string(rng, domain_separator_len),
        bls12_381_dfx_test_key(),
        memory_manager.get(MemoryId::new(memory_ids_key_manager[0])),
        memory_manager.get(MemoryId::new(memory_ids_key_manager[1])),
        memory_manager.get(MemoryId::new(memory_ids_key_manager[2])),
    )
}

fn bls12_381_dfx_test_key() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "dfx_test_key".to_string(),
    }
}
