use ic_secp256k1::{DerivationIndex, DerivationPath, PrivateKey, PublicKey};
use proptest::{collection::vec as pvec, prelude::*, prop_assert};

#[test]
fn test_remove_subnet_local_registry_records() {
    use ic_crypto_test_utils_ni_dkg::dummy_initial_dkg_transcript_with_master_key;
    use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
    use ic_interfaces_registry::{RegistryDataProvider, ZERO_REGISTRY_VERSION};
    use ic_management_canister_types_private::{
        EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve,
        VetKdKeyId,
    };
    use ic_registry_keys::{
        NODE_REWARDS_TABLE_KEY, ROOT_SUBNET_ID_KEY, make_canister_ranges_key,
        make_chain_key_enabled_subnet_list_key, make_provisional_whitelist_record_key,
        make_replica_version_key, make_subnet_list_record_key,
    };
    use ic_registry_proto_data_provider::{INITIAL_REGISTRY_VERSION, ProtoRegistryDataProvider};
    use ic_registry_resource_limits::ResourceLimits;
    use ic_registry_routing_table::RoutingTable;
    use ic_registry_subnet_features::SubnetFeatures;
    use ic_registry_subnet_type::SubnetType;
    use ic_types::{CanisterId, PrincipalId, ReplicaVersion, SubnetId};
    use ic_types_cycles::CanisterCyclesCostSchedule;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::Arc;

    let seed = [42_u8; 32];
    let mut node_rng = StdRng::from_seed(seed);
    let nodes: Vec<super::StateMachineNode> = (0..4)
        .map(|_| super::StateMachineNode::new(&mut node_rng))
        .collect();
    let (ni_dkg_transcript, _) =
        dummy_initial_dkg_transcript_with_master_key(&mut StdRng::from_seed(seed));
    let public_key = (&ni_dkg_transcript).try_into().unwrap();
    let public_key_der = threshold_sig_public_key_to_der(public_key).unwrap();
    let subnet_id = PrincipalId::new_self_authenticating(&public_key_der).into();

    let chain_key_ids: Vec<MasterPublicKeyId> = vec![
        MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_ecdsa_key".to_string(),
        }),
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "test_schnorr_key".to_string(),
        }),
        MasterPublicKeyId::VetKd(VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: "test_vetkd_key".to_string(),
        }),
    ];
    let chain_keys_enabled_status: BTreeMap<MasterPublicKeyId, bool> = chain_key_ids
        .iter()
        .map(|key_id| (key_id.clone(), true))
        .collect();
    let chain_keys: BTreeMap<MasterPublicKeyId, Vec<SubnetId>> = chain_key_ids
        .iter()
        .map(|key_id| (key_id.clone(), vec![subnet_id]))
        .collect();

    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
    super::add_initial_registry_records(registry_data_provider.clone());
    super::add_global_registry_records(
        subnet_id,
        RoutingTable::new(),
        vec![subnet_id],
        chain_keys,
        registry_data_provider.clone(),
    );
    super::add_subnet_local_registry_records(
        subnet_id,
        SubnetType::Application,
        SubnetFeatures::default(),
        &nodes,
        public_key,
        &chain_keys_enabled_status,
        ni_dkg_transcript,
        registry_data_provider.clone(),
        INITIAL_REGISTRY_VERSION,
        CanisterCyclesCostSchedule::Normal,
        vec![],
        ResourceLimits::default(),
    );

    let global_keys: HashSet<String> = HashSet::from([
        ROOT_SUBNET_ID_KEY.to_string(),
        NODE_REWARDS_TABLE_KEY.to_string(),
        make_canister_ranges_key(CanisterId::from_u64(0)),
        make_subnet_list_record_key(),
        make_provisional_whitelist_record_key(),
        make_replica_version_key(ReplicaVersion::default()),
        make_chain_key_enabled_subnet_list_key(&MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_ecdsa_key".to_string(),
        })),
        make_chain_key_enabled_subnet_list_key(&MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "test_schnorr_key".to_string(),
        })),
        make_chain_key_enabled_subnet_list_key(&MasterPublicKeyId::VetKd(VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: "test_vetkd_key".to_string(),
        })),
    ]);

    let remove_version = INITIAL_REGISTRY_VERSION.increment();
    super::remove_subnet_local_registry_records(
        subnet_id,
        &nodes,
        registry_data_provider.clone(),
        remove_version,
    );

    // Build a map: key -> latest value at or before remove_version.
    let mut latest: HashMap<String, Option<Vec<u8>>> = HashMap::new();
    let mut records: Vec<_> = registry_data_provider
        .get_updates_since(ZERO_REGISTRY_VERSION)
        .unwrap()
        .into_iter()
        .filter(|r| r.version <= remove_version)
        .collect();
    records.sort_by_key(|r| r.version);
    for r in records {
        latest.insert(r.key, r.value);
    }

    // Global/initial keys must still have values; all other keys must be tombstoned.
    for (key, value) in &latest {
        if global_keys.contains(key) {
            assert!(
                value.is_some(),
                "global/initial key '{}' should still exist but was removed",
                key
            );
        } else {
            assert!(
                value.is_none(),
                "subnet-local key '{}' should be removed but still has a value",
                key
            );
        }
    }
    // Every global/initial key must still be present.
    for key in &global_keys {
        assert!(
            latest.contains_key(key),
            "global/initial key '{}' not found in registry",
            key
        );
    }
}

#[test]
fn test_remove_chain_key_registry_records() {
    use ic_interfaces_registry::{RegistryDataProvider, ZERO_REGISTRY_VERSION};
    use ic_management_canister_types_private::{
        EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve,
        VetKdKeyId,
    };
    use ic_registry_keys::make_chain_key_enabled_subnet_list_key;
    use ic_registry_proto_data_provider::{INITIAL_REGISTRY_VERSION, ProtoRegistryDataProvider};
    use ic_registry_routing_table::RoutingTable;
    use ic_types::{PrincipalId, SubnetId};
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    let subnet_id: SubnetId = PrincipalId::new_subnet_test_id(1).into();

    let all_key_ids: Vec<MasterPublicKeyId> = vec![
        MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_ecdsa_key".to_string(),
        }),
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "test_schnorr_key".to_string(),
        }),
        MasterPublicKeyId::VetKd(VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: "test_vetkd_key".to_string(),
        }),
    ];

    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());

    // Add chain key records at the initial version.
    let chain_keys: BTreeMap<MasterPublicKeyId, Vec<SubnetId>> = all_key_ids
        .iter()
        .map(|key_id| (key_id.clone(), vec![subnet_id]))
        .collect();
    super::update_global_registry_records(
        INITIAL_REGISTRY_VERSION,
        RoutingTable::new(),
        vec![],
        chain_keys,
        registry_data_provider.clone(),
    );

    // Remove only the first two keys (ECDSA and Schnorr) at version 2.
    let keys_to_remove = &all_key_ids[..2];
    let remove_version = INITIAL_REGISTRY_VERSION.increment();
    super::remove_chain_key_registry_records(
        keys_to_remove,
        registry_data_provider.clone(),
        remove_version,
    );

    // Build map: key -> latest value at or before remove_version.
    let mut latest: HashMap<String, Option<Vec<u8>>> = HashMap::new();
    let mut records: Vec<_> = registry_data_provider
        .get_updates_since(ZERO_REGISTRY_VERSION)
        .unwrap()
        .into_iter()
        .filter(|r| r.version <= remove_version)
        .collect();
    records.sort_by_key(|r| r.version);
    for r in records {
        latest.insert(r.key, r.value);
    }

    // The removed keys must be tombstoned (value == None).
    for key_id in keys_to_remove {
        let reg_key = make_chain_key_enabled_subnet_list_key(key_id);
        assert_eq!(
            latest.get(&reg_key),
            Some(&None),
            "removed key '{}' should be tombstoned",
            reg_key
        );
    }

    // The remaining key (VetKD) must still have a value.
    let kept_key = make_chain_key_enabled_subnet_list_key(&all_key_ids[2]);
    assert!(
        latest.get(&kept_key).and_then(|v| v.as_ref()).is_some(),
        "non-removed key '{}' should still exist",
        kept_key
    );
}

#[test_strategy::proptest]
fn test_derivation_prop(
    #[strategy(pvec(pvec(any::<u8>(), 1..10), 1..10))] derivation_path_bytes: Vec<Vec<u8>>,
    #[strategy(pvec(any::<u8>(), 32))] message_hash: Vec<u8>,
) {
    let private_key_bytes =
        hex::decode("fb7d1f5b82336bb65b82bf4f27776da4db71c1ef632c6a7c171c0cbfa2ea4920").unwrap();

    let ecdsa_secret_key: PrivateKey =
        PrivateKey::deserialize_sec1(private_key_bytes.as_slice()).unwrap();

    let derivation_path = DerivationPath::new(
        derivation_path_bytes
            .into_iter()
            .map(DerivationIndex)
            .collect(),
    );

    let derived_secret_key = ecdsa_secret_key.derive_subkey(&derivation_path).0;
    let signature = derived_secret_key.sign_message_with_ecdsa(&message_hash);

    let derived_public_key = derived_secret_key.public_key();
    prop_assert!(derived_public_key.verify_ecdsa_signature(&message_hash, &signature));
}

#[test]
fn check_derived_signature() {
    const PUBLIC_KEY: [u8; 33] = [
        3, 127, 201, 44, 246, 255, 171, 193, 248, 139, 250, 124, 121, 72, 201, 158, 63, 60, 212,
        165, 56, 242, 52, 7, 67, 152, 180, 154, 67, 37, 77, 92, 151,
    ];
    const SIGNATURE: [u8; 64] = [
        178, 122, 242, 90, 8, 232, 120, 54, 167, 120, 172, 40, 88, 253, 252, 255, 31, 111, 58, 13,
        67, 49, 55, 130, 200, 29, 5, 202, 52, 184, 2, 113, 120, 2, 107, 57, 154, 50, 211, 215, 171,
        171, 98, 83, 136, 163, 197, 127, 101, 28, 102, 161, 130, 235, 127, 139, 26, 88, 217, 174,
        247, 84, 114, 86,
    ];
    const DIGEST: [u8; 32] = [
        101, 150, 83, 30, 137, 183, 4, 198, 179, 132, 194, 110, 159, 39, 111, 77, 90, 238, 166,
        150, 169, 24, 252, 246, 26, 57, 121, 75, 54, 74, 38, 28,
    ];
    const DERIVATION_PATH: [[u8; 10]; 1] = [[0, 0, 0, 0, 0, 0, 0, 0, 1, 1]];

    let derivation_path = DerivationPath::new(
        DERIVATION_PATH
            .to_vec()
            .iter()
            .map(|path| DerivationIndex(path.to_vec()))
            .collect::<Vec<_>>(),
    );

    let private_key_bytes =
        hex::decode("fb7d1f5b82336bb65b82bf4f27776da4db71c1ef632c6a7c171c0cbfa2ea4920").unwrap();

    let ecdsa_secret_key: PrivateKey =
        PrivateKey::deserialize_sec1(private_key_bytes.as_slice()).unwrap();

    let derived_key = ecdsa_secret_key.derive_subkey(&derivation_path).0;

    let signature = derived_key.sign_digest_with_ecdsa(&DIGEST);
    assert_eq!(signature, SIGNATURE);

    let derived_public_key =
        PublicKey::deserialize_sec1(&PUBLIC_KEY).expect("couldn't deserialize sec1");
    assert!(derived_public_key.verify_signature_prehashed(&DIGEST, &signature));
}

#[test]
fn public_derivation_path() {
    use ic_types::PrincipalId;

    let private_key_bytes =
        hex::decode("fb7d1f5b82336bb65b82bf4f27776da4db71c1ef632c6a7c171c0cbfa2ea4920").unwrap();

    let ecdsa_secret_key: PrivateKey =
        PrivateKey::deserialize_sec1(private_key_bytes.as_slice()).unwrap();

    let caller = PrincipalId::new_user_test_id(1);

    let path = DerivationPath::from_canister_id_and_path(caller.as_slice(), &[]);

    let derived_key = ecdsa_secret_key
        .public_key()
        .derive_subkey(&path)
        .0
        .serialize_sec1(true);

    assert_eq!(
        hex::encode(&derived_key),
        "03fda02786d72d691d807a10a3de60522b664472ec2f06a704cc34ebe2fc26724c"
    );
}
