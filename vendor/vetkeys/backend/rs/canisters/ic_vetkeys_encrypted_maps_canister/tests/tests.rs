use assert_matches::assert_matches;
use candid::{decode_one, encode_args, encode_one, CandidType, Principal};
// use ic_stable_structures::storable::Blob;
// use ic_vetkeys::encrypted_maps::EncryptedMapData;
use ic_vetkeys::encrypted_maps::{VetKey, VetKeyVerificationKey};
use ic_vetkeys::key_manager::key_id_to_vetkd_input;
use ic_vetkeys::types::{AccessControl, AccessRights, ByteBuf, TransportKey};
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey};
use pocket_ic::{PocketIc, PocketIcBuilder};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;
use std::path::Path;
use strum::IntoEnumIterator;

#[test]
fn should_obtain_verification_key() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let verification_key: VetKeyVerificationKey = env.update(
        env.principal_0,
        "get_vetkey_verification_key",
        encode_one(()).unwrap(),
    );
    assert_eq!(verification_key.as_ref().len(), 96);
    assert_ne!(verification_key, VetKeyVerificationKey::from(vec![0; 96]));
}

#[test]
fn should_obtain_owned_encrypted_vetkey() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let map_owner = env.principal_0;
    let map_name = random_map_name(rng);
    let transport_key = random_transport_key(rng);
    let transport_key_bytes = TransportKey::from(transport_key.public_key());
    let encrypted_vetkey = env
        .update::<Result<VetKey, String>>(
            env.principal_0,
            "get_encrypted_vetkey",
            encode_args((map_owner, map_name, transport_key_bytes)).unwrap(),
        )
        .unwrap();

    assert_eq!(encrypted_vetkey.as_ref().len(), 192);
    assert_ne!(encrypted_vetkey, VetKeyVerificationKey::from(vec![0; 192]));
}

#[test]
fn encrypted_vetkey_should_validate() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);

    let verification_key_bytes: VetKeyVerificationKey = env.update(
        env.principal_0,
        "get_vetkey_verification_key",
        encode_one(()).unwrap(),
    );

    let map_owner = env.principal_0;
    let map_name = random_map_name(rng);
    let transport_key = random_transport_key(rng);
    let transport_key_bytes = TransportKey::from(transport_key.public_key());
    let encrypted_vetkey_bytes = env
        .update::<Result<VetKey, String>>(
            env.principal_0,
            "get_encrypted_vetkey",
            encode_args((map_owner, map_name.clone(), transport_key_bytes)).unwrap(),
        )
        .unwrap();

    let derived_public_key =
        DerivedPublicKey::deserialize(verification_key_bytes.as_ref()).unwrap();
    let encrypted_vetkey = EncryptedVetKey::deserialize(encrypted_vetkey_bytes.as_ref()).unwrap();

    encrypted_vetkey
        .decrypt_and_verify(
            &transport_key,
            &derived_public_key,
            &key_id_to_vetkd_input(map_owner, map_name.as_ref()),
        )
        .expect("failed to decrypt and verify `vetkey");
}

#[test]
fn map_sharing_should_work() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);

    let verification_key_bytes: VetKeyVerificationKey = env.update(
        env.principal_0,
        "get_vetkey_verification_key",
        encode_one(()).unwrap(),
    );

    let map_owner = env.principal_0;
    let map_name = random_map_name(rng);

    let prev_rights = env
        .update::<Result<Option<AccessRights>, String>>(
            env.principal_0,
            "set_user_rights",
            encode_args((
                map_owner,
                map_name.clone(),
                env.principal_1,
                AccessRights::ReadWriteManage,
            ))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(prev_rights, None);

    let current_rights_owner = env
        .query::<Result<Option<AccessRights>, String>>(
            env.principal_0,
            "get_user_rights",
            encode_args((map_owner, map_name.clone(), env.principal_0)).unwrap(),
        )
        .unwrap();
    assert_eq!(current_rights_owner, Some(AccessRights::ReadWriteManage));

    let current_rights_shared = env
        .query::<Result<Option<AccessRights>, String>>(
            env.principal_1,
            "get_user_rights",
            encode_args((map_owner, map_name.clone(), env.principal_1)).unwrap(),
        )
        .unwrap();
    assert_eq!(current_rights_shared, Some(AccessRights::ReadWriteManage));

    let mut get_vetkey = |caller: Principal| -> Vec<u8> {
        let transport_key = random_transport_key(rng);
        let transport_key_bytes = TransportKey::from(transport_key.public_key());
        let encrypted_vetkey_bytes = env
            .update::<Result<VetKey, String>>(
                caller,
                "get_encrypted_vetkey",
                encode_args((map_owner, map_name.clone(), transport_key_bytes)).unwrap(),
            )
            .unwrap();

        let derived_public_key =
            DerivedPublicKey::deserialize(verification_key_bytes.as_ref()).unwrap();
        let encrypted_vetkey =
            EncryptedVetKey::deserialize(encrypted_vetkey_bytes.as_ref()).unwrap();

        let vetkey = encrypted_vetkey
            .decrypt_and_verify(
                &transport_key,
                &derived_public_key,
                &key_id_to_vetkd_input(map_owner, map_name.as_ref()),
            )
            .expect("failed to decrypt and verify `vetkey");

        vetkey.signature_bytes().as_ref().to_vec()
    };

    assert_eq!(get_vetkey(env.principal_0), get_vetkey(env.principal_1));
}

#[test]
fn should_remove_map_values() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let map_key = random_map_key(rng);
    let encrypted_value = random_encrypted_value(rng);

    // Add an entry into the map
    env.update::<Result<Option<ByteBuf>, String>>(
        caller,
        "insert_encrypted_value",
        encode_args((
            caller,
            map_name.clone(),
            map_key.clone(),
            encrypted_value.clone(),
        ))
        .unwrap(),
    )
    .unwrap();

    // Remove map values and ensure the removed key is returned
    let result = env.update::<Result<Vec<ByteBuf>, String>>(
        caller,
        "remove_map_values",
        encode_args((caller, map_name.clone())).unwrap(),
    );
    assert_eq!(result, Ok(vec![map_key.clone()]));

    // Ensure that the map is indeed empty afterwards
    let remaining_values = env
        .query::<Result<Vec<(ByteBuf, ByteBuf)>, String>>(
            caller,
            "get_encrypted_values_for_map",
            encode_args((caller, map_name)).unwrap(),
        )
        .unwrap();
    assert_eq!(remaining_values, vec![]);
}

#[test]
fn should_fail_to_delete_map_values_by_unauthorized() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let unauthorized = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let map_key = random_map_key(rng);
    let encrypted_value = random_encrypted_value(rng);

    env.update::<Result<Option<ByteBuf>, String>>(
        caller,
        "insert_encrypted_value",
        encode_args((caller, map_name.clone(), map_key.clone(), encrypted_value)).unwrap(),
    )
    .unwrap();

    let result = env.update::<Result<Vec<ByteBuf>, String>>(
        unauthorized,
        "remove_map_values",
        encode_args((caller, map_name)).unwrap(),
    );
    assert_eq!(result, Err("unauthorized".to_string()));
}

#[test]
fn should_add_user_to_map() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let user_to_be_added = random_self_authenticating_principal(rng);
    let access_rights = random_access_rights(rng);

    assert_eq!(
        env.query::<Result<Option<AccessRights>, String>>(
            caller,
            "get_user_rights",
            encode_args((caller, map_name.clone(), user_to_be_added)).unwrap(),
        ),
        Ok(None)
    );

    assert_eq!(
        env.update::<Result<Option<AccessRights>, String>>(
            caller,
            "set_user_rights",
            encode_args((caller, map_name.clone(), user_to_be_added, access_rights)).unwrap(),
        ),
        Ok(None)
    );

    assert_eq!(
        env.update::<Result<Option<AccessRights>, String>>(
            caller,
            "set_user_rights",
            encode_args((caller, map_name.clone(), user_to_be_added, access_rights)).unwrap(),
        ),
        Ok(Some(access_rights))
    );

    assert_eq!(
        env.query::<Result<Option<AccessRights>, String>>(
            caller,
            "get_user_rights",
            encode_args((caller, map_name.clone(), user_to_be_added)).unwrap(),
        ),
        Ok(Some(access_rights))
    );
}

#[test]
fn should_fail_to_invoke_operations_by_unauthorized() {
    // Note: Unauthorized access to
    // * insert_encrypted_value is tested in should_fail_to_add_a_key_to_map_by_unauthorized and should_fail_modify_key_value_in_map_by_unauthorized
    // * remove_encrypted_value is tested in should_fail_to_remove_a_key_from_map_by_unauthorized

    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let unauthorized = random_self_authenticating_principal(rng);
    let owner = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let map_key = random_map_key(rng);
    let _encrypted_value = random_encrypted_value(rng);

    assert_eq!(
        env.query::<Result<Option<AccessRights>, String>>(
            unauthorized,
            "get_user_rights",
            encode_args((owner, map_name.clone(), unauthorized)).unwrap(),
        ),
        Err("unauthorized".to_string())
    );

    assert_eq!(
        env.query::<Result<Option<ByteBuf>, String>>(
            unauthorized,
            "get_encrypted_value",
            encode_args((owner, map_name.clone(), map_key.clone())).unwrap(),
        ),
        Err("unauthorized".to_string())
    );

    assert_eq!(
        env.query::<Result<Vec<(ByteBuf, ByteBuf)>, String>>(
            unauthorized,
            "get_encrypted_values_for_map",
            encode_args((owner, map_name.clone())).unwrap(),
        ),
        Err("unauthorized".to_string())
    );

    assert_eq!(
        env.query::<Result<Vec<(Principal, AccessRights)>, String>>(
            unauthorized,
            "get_shared_user_access_for_map",
            encode_args((owner, map_name.clone())).unwrap(),
        ),
        Err("unauthorized".to_string())
    );

    let transport_key = random_transport_key(rng);
    let transport_key_bytes = TransportKey::from(transport_key.public_key());
    assert_eq!(
        env.update::<Result<VetKey, String>>(
            unauthorized,
            "get_encrypted_vetkey",
            encode_args((owner, map_name.clone(), transport_key_bytes)).unwrap(),
        ),
        Err("unauthorized".to_string())
    );

    for _ in 0..2 {
        assert_eq!(
            env.update::<Result<Vec<ByteBuf>, String>>(
                unauthorized,
                "remove_map_values",
                encode_args((owner, map_name.clone())).unwrap(),
            ),
            Err("unauthorized".to_string())
        );

        assert_eq!(
            env.update::<Result<Option<AccessRights>, String>>(
                unauthorized,
                "remove_user",
                encode_args((owner, map_name.clone(), unauthorized)).unwrap(),
            ),
            Err("unauthorized".to_string())
        );

        assert_eq!(
            env.update::<Result<Option<AccessRights>, String>>(
                unauthorized,
                "set_user_rights",
                encode_args((owner, map_name.clone(), unauthorized, AccessRights::Read)).unwrap(),
            ),
            Err("unauthorized".to_string())
        );

        env.update::<Result<Option<AccessRights>, String>>(
            owner,
            "set_user_rights",
            encode_args((owner, map_name.clone(), unauthorized, AccessRights::Read)).unwrap(),
        )
        .unwrap();
    }

    env.update::<Result<Option<AccessRights>, String>>(
        owner,
        "set_user_rights",
        encode_args((
            owner,
            map_name.clone(),
            unauthorized,
            AccessRights::ReadWrite,
        ))
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        env.update::<Result<Option<AccessRights>, String>>(
            unauthorized,
            "set_user_rights",
            encode_args((owner, map_name.clone(), unauthorized, AccessRights::Read)).unwrap(),
        ),
        Err("unauthorized".to_string())
    );
}

#[test]
fn should_remove_user_from_map() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let user_to_be_added = random_self_authenticating_principal(rng);
    let access_rights = random_access_rights(rng);

    assert_eq!(
        env.update::<Result<Option<AccessRights>, String>>(
            caller,
            "set_user_rights",
            encode_args((caller, map_name.clone(), user_to_be_added, access_rights)).unwrap(),
        ),
        Ok(None)
    );

    assert_eq!(
        env.update::<Result<Option<AccessRights>, String>>(
            caller,
            "remove_user",
            encode_args((caller, map_name.clone(), user_to_be_added)).unwrap(),
        ),
        Ok(Some(access_rights))
    );

    assert_eq!(
        env.query::<Result<Option<AccessRights>, String>>(
            caller,
            "get_user_rights",
            encode_args((caller, map_name.clone(), user_to_be_added)).unwrap(),
        ),
        Ok(None)
    );
}

#[test]
fn should_fail_add_or_remove_user_by_unauthorized() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let mut unauthorized_callers = vec![random_self_authenticating_principal(rng)];

    for access_rights in AccessRights::iter() {
        if access_rights.can_get_user_rights() {
            continue;
        }
        let user_to_be_added = random_self_authenticating_principal(rng);

        assert_matches!(
            env.update::<Result<Option<AccessRights>, String>>(
                caller,
                "set_user_rights",
                encode_args((caller, map_name.clone(), user_to_be_added, access_rights)).unwrap(),
            ),
            Ok(_)
        );

        unauthorized_callers.push(user_to_be_added);
    }

    for unauthorized_caller in unauthorized_callers {
        for target in [random_self_authenticating_principal(rng), caller] {
            assert_eq!(
                env.update::<Result<Option<AccessRights>, String>>(
                    unauthorized_caller,
                    "remove_user",
                    encode_args((caller, map_name.clone(), target)).unwrap(),
                ),
                Err("unauthorized".to_string())
            );
            assert_eq!(
                env.update::<Result<Option<AccessRights>, String>>(
                    unauthorized_caller,
                    "set_user_rights",
                    encode_args((caller, map_name.clone(), target, AccessRights::Read)).unwrap(),
                ),
                Err("unauthorized".to_string())
            );
        }
    }
}

#[test]
fn should_add_a_key_to_map() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let map_key = random_map_key(rng);
    let encrypted_value = random_encrypted_value(rng);

    assert_eq!(
        env.update::<Result<Option<ByteBuf>, String>>(
            caller,
            "insert_encrypted_value",
            encode_args((
                caller,
                map_name.clone(),
                map_key.clone(),
                encrypted_value.clone()
            ))
            .unwrap(),
        ),
        Ok(None)
    );

    assert_eq!(
        env.query::<Result<Option<ByteBuf>, String>>(
            caller,
            "get_encrypted_value",
            encode_args((caller, map_name.clone(), map_key)).unwrap(),
        ),
        Ok(Some(encrypted_value))
    );
}

#[test]
fn should_fail_to_add_a_key_to_map_by_unauthorized() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let unauthorized_caller = random_self_authenticating_principal(rng);
    let map_key = random_map_key(rng);
    let encrypted_value = random_encrypted_value(rng);

    assert_eq!(
        env.update::<Result<Option<ByteBuf>, String>>(
            unauthorized_caller,
            "insert_encrypted_value",
            encode_args((
                caller,
                map_name.clone(),
                map_key.clone(),
                encrypted_value.clone()
            ))
            .unwrap(),
        ),
        Err("unauthorized".to_string())
    );

    let readonly_caller = random_self_authenticating_principal(rng);

    assert_eq!(
        env.update::<Result<Option<AccessRights>, String>>(
            caller,
            "set_user_rights",
            encode_args((
                caller,
                map_name.clone(),
                readonly_caller,
                AccessRights::Read
            ))
            .unwrap(),
        ),
        Ok(None)
    );

    assert_eq!(
        env.update::<Result<Option<ByteBuf>, String>>(
            readonly_caller,
            "insert_encrypted_value",
            encode_args((caller, map_name.clone(), map_key.clone(), encrypted_value)).unwrap(),
        ),
        Err("unauthorized".to_string())
    );
}

#[test]
fn should_remove_key_from_map() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let map_key = random_map_key(rng);
    let encrypted_value = random_encrypted_value(rng);

    env.update::<Result<Option<ByteBuf>, String>>(
        caller,
        "insert_encrypted_value",
        encode_args((
            caller,
            map_name.clone(),
            map_key.clone(),
            encrypted_value.clone(),
        ))
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        env.update::<Result<Option<ByteBuf>, String>>(
            caller,
            "remove_encrypted_value",
            encode_args((caller, map_name.clone(), map_key.clone())).unwrap(),
        ),
        Ok(Some(encrypted_value))
    );

    assert_eq!(
        env.query::<Result<Option<ByteBuf>, String>>(
            caller,
            "get_encrypted_value",
            encode_args((caller, map_name.clone(), map_key)).unwrap(),
        ),
        Ok(None)
    );
}

#[test]
fn should_fail_to_remove_a_key_from_map_by_unauthorized() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let map_key = random_map_key(rng);
    let encrypted_value = random_encrypted_value(rng);

    env.update::<Result<Option<ByteBuf>, String>>(
        caller,
        "insert_encrypted_value",
        encode_args((caller, map_name.clone(), map_key.clone(), encrypted_value)).unwrap(),
    )
    .unwrap();

    let unauthorized_caller = random_self_authenticating_principal(rng);
    assert_eq!(
        env.update::<Result<Option<ByteBuf>, String>>(
            unauthorized_caller,
            "remove_encrypted_value",
            encode_args((caller, map_name.clone(), map_key.clone())).unwrap(),
        ),
        Err("unauthorized".to_string())
    );

    let readonly_caller = random_self_authenticating_principal(rng);

    assert_eq!(
        env.update::<Result<Option<AccessRights>, String>>(
            caller,
            "set_user_rights",
            encode_args((
                caller,
                map_name.clone(),
                readonly_caller,
                AccessRights::Read
            ))
            .unwrap(),
        ),
        Ok(None)
    );

    assert_eq!(
        env.update::<Result<Option<ByteBuf>, String>>(
            readonly_caller,
            "remove_encrypted_value",
            encode_args((caller, map_name.clone(), map_key.clone())).unwrap(),
        ),
        Err("unauthorized".to_string())
    );
}

#[test]
fn should_access_map_values() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);

    let mut authorized_users = vec![(caller, AccessRights::ReadWriteManage)];
    let mut keyvals = vec![];

    for _ in 0..3 {
        let map_key = random_map_key(rng);
        let encrypted_value = random_small_encrypted_value(rng);
        env.update::<Result<Option<ByteBuf>, String>>(
            caller,
            "insert_encrypted_value",
            encode_args((
                caller,
                map_name.clone(),
                map_key.clone(),
                encrypted_value.clone(),
            ))
            .unwrap(),
        )
        .unwrap();

        for access_rights in AccessRights::iter() {
            let user_to_be_added = random_self_authenticating_principal(rng);
            assert_eq!(
                env.update::<Result<Option<AccessRights>, String>>(
                    caller,
                    "set_user_rights",
                    encode_args((caller, map_name.clone(), user_to_be_added, access_rights))
                        .unwrap(),
                ),
                Ok(None)
            );
            authorized_users.push((user_to_be_added, access_rights));
        }

        keyvals.push((map_key, encrypted_value));
    }

    for (map_key, encrypted_value) in keyvals.clone() {
        for (user, _access_rights) in authorized_users.iter() {
            assert_eq!(
                env.query::<Result<Option<ByteBuf>, String>>(
                    *user,
                    "get_encrypted_value",
                    encode_args((caller, map_name.clone(), map_key.clone())).unwrap(),
                ),
                Ok(Some(encrypted_value.clone()))
            );
        }
    }

    for (user, _access_rights) in authorized_users.clone() {
        let expected_map = BTreeMap::from_iter(keyvals.clone());
        let computed_map_single = BTreeMap::from_iter(
            env.query::<Result<Vec<(ByteBuf, ByteBuf)>, String>>(
                user,
                "get_encrypted_values_for_map",
                encode_args((caller, map_name.clone())).unwrap(),
            )
            .expect("failed to obtain values"),
        );
        assert_eq!(expected_map.clone(), computed_map_single);

        let all_values = env.query::<Vec<((Principal, ByteBuf), Vec<(ByteBuf, ByteBuf)>)>>(
            user,
            "get_all_accessible_encrypted_values",
            encode_one(()).unwrap(),
        );
        assert_eq!(all_values.len(), 1);

        // let all_maps = env.query::<Vec<EncryptedMapData<AccessRights>>>(
        //     user,
        //     "get_all_accessible_encrypted_maps",
        //     encode_one(()).unwrap(),
        // );

        // assert_eq!(
        //     all_values,
        //     all_maps
        //         .iter()
        //         .map(|m| (
        //             (
        //                 m.map_owner,
        //                 Blob::<32>::try_from(m.map_name.as_ref()).unwrap()
        //             ),
        //             m.keyvals
        //                 .iter()
        //                 .map(|(map_key, value)| (
        //                     Blob::<32>::try_from(map_key.as_ref()).unwrap(),
        //                     value.clone()
        //                 ))
        //                 .collect::<Vec<_>>()
        //         ))
        //         .collect::<Vec<_>>()
        // );

        let all_destructured = all_values.into_iter().next().unwrap();
        assert_eq!((caller, map_name.clone()), all_destructured.0);
        let computed_map_wildcard = all_destructured.1;
        assert_eq!(
            expected_map.clone(),
            BTreeMap::from_iter(computed_map_wildcard)
        );

        // for map in all_maps {
        //     if access_rights.can_get_user_rights() {
        //         assert_eq!(
        //             BTreeMap::<Principal, AccessRights>::from_iter(
        //                 map.access_control
        //                     .into_iter()
        //                     .chain(std::iter::once((caller, access_rights)))
        //             ),
        //             BTreeMap::from_iter(authorized_users.clone().into_iter())
        //         );
        //     } else {
        //         assert_eq!(map.access_control, vec![]);
        //     }
        // }
    }
}

#[test]
fn should_modify_key_value_in_map() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let map_key = random_map_key(rng);
    let encrypted_value = random_encrypted_value(rng);

    assert_eq!(
        env.update::<Result<Option<ByteBuf>, String>>(
            caller,
            "insert_encrypted_value",
            encode_args((
                caller,
                map_name.clone(),
                map_key.clone(),
                encrypted_value.clone(),
            ))
            .unwrap(),
        ),
        Ok(None)
    );

    let new_encrypted_value = random_encrypted_value(rng);
    assert_eq!(
        env.update::<Result<Option<ByteBuf>, String>>(
            caller,
            "insert_encrypted_value",
            encode_args((
                caller,
                map_name.clone(),
                map_key.clone(),
                new_encrypted_value.clone()
            ))
            .unwrap(),
        ),
        Ok(Some(encrypted_value))
    );

    assert_eq!(
        env.query::<Result<Option<ByteBuf>, String>>(
            caller,
            "get_encrypted_value",
            encode_args((caller, map_name.clone(), map_key)).unwrap(),
        ),
        Ok(Some(new_encrypted_value))
    );
}

#[test]
fn should_fail_modify_key_value_in_map_by_unauthorized() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let map_name = random_map_name(rng);
    let map_key = random_map_key(rng);
    let encrypted_value = random_encrypted_value(rng);

    env.update::<Result<Option<ByteBuf>, String>>(
        caller,
        "insert_encrypted_value",
        encode_args((
            caller,
            map_name.clone(),
            map_key.clone(),
            encrypted_value.clone(),
        ))
        .unwrap(),
    )
    .unwrap();

    let unauthorized_caller = random_self_authenticating_principal(rng);
    let new_encrypted_value = random_encrypted_value(rng);
    assert_eq!(
        env.update::<Result<Option<ByteBuf>, String>>(
            unauthorized_caller,
            "insert_encrypted_value",
            encode_args((
                caller,
                map_name.clone(),
                map_key.clone(),
                new_encrypted_value.clone()
            ))
            .unwrap(),
        ),
        Err("unauthorized".to_string())
    );

    let readonly_caller = random_self_authenticating_principal(rng);

    assert_eq!(
        env.update::<Result<Option<AccessRights>, String>>(
            caller,
            "set_user_rights",
            encode_args((
                caller,
                map_name.clone(),
                readonly_caller,
                AccessRights::Read
            ))
            .unwrap(),
        ),
        Ok(None)
    );

    assert_eq!(
        env.update::<Result<Option<ByteBuf>, String>>(
            readonly_caller,
            "insert_encrypted_value",
            encode_args((caller, map_name.clone(), map_key, new_encrypted_value)).unwrap(),
        ),
        Err("unauthorized".to_string())
    );
}

#[test]
fn should_get_owned_map_names() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);
    let caller = random_self_authenticating_principal(rng);
    let mut expected_map_names = vec![];

    for _ in 0..7 {
        let map_names = env.query::<Vec<ByteBuf>>(
            caller,
            "get_owned_non_empty_map_names",
            encode_one(()).unwrap(),
        );
        assert_eq!(map_names.len(), expected_map_names.len());
        for map_name in expected_map_names.iter() {
            assert!(map_names.contains(map_name));
        }

        let map_name = random_map_name(rng);
        expected_map_names.push(map_name.clone());

        for _ in 1..3 {
            let map_key = random_map_key(rng);
            let encrypted_value = random_encrypted_value(rng);
            env.update::<Result<Option<ByteBuf>, String>>(
                caller,
                "insert_encrypted_value",
                encode_args((caller, map_name.clone(), map_key, encrypted_value)).unwrap(),
            )
            .unwrap();
        }

        let map_names = env.query::<Vec<ByteBuf>>(
            caller,
            "get_owned_non_empty_map_names",
            encode_one(()).unwrap(),
        );
        assert_eq!(map_names.len(), expected_map_names.len());
        for map_name in expected_map_names.iter() {
            assert!(map_names.contains(map_name));
        }

        let should_remove_map = rng.gen_bool(0.2);

        if should_remove_map {
            env.update::<Result<Vec<ByteBuf>, String>>(
                caller,
                "remove_map_values",
                encode_args((caller, map_name.clone())).unwrap(),
            )
            .unwrap();
            expected_map_names.pop();
        }
    }
}

pub fn reproducible_rng() -> ChaCha20Rng {
    let seed = rand::thread_rng().gen();
    println!("RNG seed: {seed:?}");
    ChaCha20Rng::from_seed(seed)
}

struct TestEnvironment {
    pic: PocketIc,
    example_canister_id: Principal,
    principal_0: Principal,
    principal_1: Principal,
}

impl TestEnvironment {
    fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let pic = PocketIcBuilder::new()
            .with_application_subnet()
            .with_ii_subnet()
            .with_fiduciary_subnet()
            .with_nonmainnet_features(true)
            .build();

        let example_canister_id = pic.create_canister();
        pic.add_cycles(example_canister_id, 2_000_000_000_000);

        let example_wasm_bytes = load_encrypted_maps_example_canister_wasm();
        pic.install_canister(
            example_canister_id,
            example_wasm_bytes,
            encode_one("dfx_test_key").unwrap(),
            None,
        );

        // Make sure the canister is properly initialized
        fast_forward(&pic, 5);

        Self {
            pic,
            example_canister_id,
            principal_0: random_self_authenticating_principal(rng),
            principal_1: random_self_authenticating_principal(rng),
        }
    }

    fn update<T: CandidType + for<'de> candid::Deserialize<'de>>(
        &self,
        caller: Principal,
        method_name: &str,
        args: Vec<u8>,
    ) -> T {
        let reply = self
            .pic
            .update_call(self.example_canister_id, caller, method_name, args);
        match reply {
            Ok(data) => decode_one(&data).expect("failed to decode reply"),
            Err(user_error) => panic!("canister returned a user error: {user_error}"),
        }
    }

    fn query<T: CandidType + for<'de> candid::Deserialize<'de>>(
        &self,
        caller: Principal,
        method_name: &str,
        args: Vec<u8>,
    ) -> T {
        let reply = self
            .pic
            .query_call(self.example_canister_id, caller, method_name, args);
        match reply {
            Ok(data) => decode_one(&data).expect("failed to decode reply"),
            Err(user_error) => panic!("canister returned a user error: {user_error}"),
        }
    }
}

fn load_encrypted_maps_example_canister_wasm() -> Vec<u8> {
    let wasm_path_string = match std::env::var("CUSTOM_WASM_PATH") {
        Ok(path) if !path.is_empty() => path,
        _ => format!(
            "{}/target/wasm32-unknown-unknown/release/ic_vetkeys_encrypted_maps_canister.wasm",
            git_root_dir()
        ),
    };
    let wasm_path = Path::new(&wasm_path_string);
    std::fs::read(wasm_path)
        .expect("wasm does not exist - run `cargo build --release --target wasm32-unknown-unknown`")
}

fn random_transport_key<R: Rng + CryptoRng>(rng: &mut R) -> TransportSecretKey {
    let mut seed = vec![0u8; 32];
    rng.fill_bytes(&mut seed);
    TransportSecretKey::from_seed(seed).unwrap()
}

fn fast_forward(ic: &PocketIc, ticks: u64) {
    for _ in 0..ticks - 1 {
        ic.tick();
    }
}

fn random_map_name<R: Rng + CryptoRng>(rng: &mut R) -> ByteBuf {
    let length = rng.gen_range(0..32);
    let mut map_name = vec![0u8; length];
    rng.fill_bytes(&mut map_name);
    ByteBuf::from(map_name)
}

pub fn random_self_authenticating_principal<R: Rng + CryptoRng>(rng: &mut R) -> Principal {
    let mut fake_public_key = vec![0u8; 32];
    rng.fill_bytes(&mut fake_public_key);
    Principal::self_authenticating::<&[u8]>(fake_public_key.as_ref())
}

fn git_root_dir() -> String {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("Failed to execute git command");
    assert!(output.status.success());
    let root_dir_with_newline =
        String::from_utf8(output.stdout).expect("Failed to convert stdout to string");
    root_dir_with_newline.trim_end_matches('\n').to_string()
}

fn random_map_key<R: Rng + CryptoRng>(rng: &mut R) -> ByteBuf {
    let length = rng.gen_range(0..32);
    let mut map_key = vec![0u8; length];
    rng.fill_bytes(&mut map_key);
    ByteBuf::from(map_key)
}

fn random_encrypted_value<R: Rng + CryptoRng>(rng: &mut R) -> ByteBuf {
    let length = rng.gen_range(0..2_000_000);
    let mut encrypted_value = vec![0u8; length];
    rng.fill_bytes(&mut encrypted_value);
    ByteBuf::from(encrypted_value)
}

fn random_small_encrypted_value<R: Rng + CryptoRng>(rng: &mut R) -> ByteBuf {
    let length = rng.gen_range(0..1_000);
    let mut encrypted_value = vec![0u8; length];
    rng.fill_bytes(&mut encrypted_value);
    ByteBuf::from(encrypted_value)
}

fn random_access_rights<R: Rng + CryptoRng>(rng: &mut R) -> AccessRights {
    loop {
        if let Some(ar) = AccessRights::from_repr(rng.gen()) {
            return ar;
        }
    }
}
