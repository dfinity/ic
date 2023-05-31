use ic_config::crypto::CryptoConfig;
use ic_crypto_temp_crypto::{TempCryptoComponent, TempCryptoComponentGeneric};
use ic_crypto_test_utils::empty_fake_registry;
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_types_test_utils::ids::node_test_id;
use std::sync::Arc;

const NODE_ID: u64 = 42;

#[test]
fn should_delete_tempdir_when_temp_crypto_goes_out_of_scope() {
    let path = {
        let temp_crypto = TempCryptoComponent::builder()
            .with_registry(empty_fake_registry())
            .with_node_id(node_test_id(NODE_ID))
            .build();
        temp_crypto.temp_dir_path().to_path_buf()
    };
    assert!(!path.exists());
}

#[test]
fn should_create_tempdir_as_directory() {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(empty_fake_registry())
        .with_node_id(node_test_id(NODE_ID))
        .build();
    assert!(temp_crypto.temp_dir_path().is_dir());
}

#[test]
fn should_create_with_tempdir_that_exists() {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(empty_fake_registry())
        .with_node_id(node_test_id(NODE_ID))
        .build();
    assert!(temp_crypto.temp_dir_path().exists());
}

#[test]
fn should_set_correct_tempdir_permissions() {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(empty_fake_registry())
        .with_node_id(node_test_id(NODE_ID))
        .build();
    let result = CryptoConfig::check_dir_has_required_permissions(temp_crypto.temp_dir_path());
    assert!(result.is_ok(), "{:?}", result);
}

mod vault_rng {
    use super::*;
    use assert_matches::assert_matches;
    use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
    use ic_crypto_internal_csp::Csp;
    use ic_crypto_temp_crypto::{EcdsaSubnetConfig, NodeKeysToGenerate};
    use ic_interfaces::crypto::KeyManager;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities::FastForwardTimeSource;
    use rand::SeedableRng;
    use std::time::Duration;

    const TWO_WEEKS: Duration = Duration::from_secs(2 * 7 * 24 * 60 * 60);
    const REG_V1: RegistryVersion = RegistryVersion::new(1);
    const SUBNET_ID: SubnetId = SubnetId::new(PrincipalId::new(29, [0xfc; 29]));

    const SEED_0: [u8; 32] = [0u8; 32];
    const SEED_1: [u8; 32] = [1u8; 32];

    // Should produce same iDKG keys and key rotation results for same configs and RNGs.
    #[test]
    fn should_set_correct_rng_in_local_vault() {
        let temp_crypto_0_rng_0 = new_idkg_crypto_with_rng_and_opt_remote_vault(
            ReproducibleRng::from_seed(SEED_0),
            false,
        );
        let temp_crypto_1_rng_0 = new_idkg_crypto_with_rng_and_opt_remote_vault(
            ReproducibleRng::from_seed(SEED_0),
            false,
        );
        let temp_crypto_2_rng_1 = new_idkg_crypto_with_rng_and_opt_remote_vault(
            ReproducibleRng::from_seed(SEED_1),
            false,
        );

        test_vault_consistency(
            temp_crypto_0_rng_0,
            temp_crypto_1_rng_0,
            temp_crypto_2_rng_1,
        );
    }

    // Should produce same iDKG keys and key rotation results for same configs and RNGs.
    #[test]
    fn should_set_correct_rng_in_remote_vault() {
        let temp_crypto_0_rng_0 =
            new_idkg_crypto_with_rng_and_opt_remote_vault(ReproducibleRng::from_seed(SEED_0), true);
        let temp_crypto_1_rng_0 =
            new_idkg_crypto_with_rng_and_opt_remote_vault(ReproducibleRng::from_seed(SEED_0), true);
        let temp_crypto_2_rng_1 =
            new_idkg_crypto_with_rng_and_opt_remote_vault(ReproducibleRng::from_seed(SEED_1), true);

        test_vault_consistency(
            temp_crypto_0_rng_0,
            temp_crypto_1_rng_0,
            temp_crypto_2_rng_1,
        );
    }

    fn new_idkg_crypto_with_rng_and_opt_remote_vault(
        rng: ReproducibleRng,
        with_remote_vault: bool,
    ) -> TempCryptoComponentGeneric<Csp, ReproducibleRng> {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(0));
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
        let time = FastForwardTimeSource::new();
        let mut crypto_component_builder = TempCryptoComponent::builder()
            .with_keys(NodeKeysToGenerate::all())
            .with_registry_client_and_data(
                Arc::clone(&registry_client) as Arc<_>,
                Arc::clone(&registry_data) as Arc<_>,
            )
            .with_time_source(Arc::clone(&time) as Arc<_>)
            .with_node_id(node_id)
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                SUBNET_ID,
                Some(node_id),
                Some(TWO_WEEKS),
            ))
            .with_rng(rng);
        if with_remote_vault {
            crypto_component_builder = crypto_component_builder.with_remote_vault();
        }

        let crypto_component = crypto_component_builder.build();

        registry_client.reload();
        crypto_component
    }

    /// Tests the vault consistency by checking (in)equality of the initially
    /// generated keys, then rotating keys and checking the (in)equality again.
    /// The first two crypto components are initialized with the same RNG seed,
    /// whereas the last one with a different RNG seed.
    fn test_vault_consistency(
        temp_crypto_0_rng_0: TempCryptoComponentGeneric<Csp, ReproducibleRng>,
        temp_crypto_1_rng_0: TempCryptoComponentGeneric<Csp, ReproducibleRng>,
        temp_crypto_2_rng_1: TempCryptoComponentGeneric<Csp, ReproducibleRng>,
    ) {
        use ic_protobuf::registry::crypto::v1::PublicKey;
        fn get_idkg_keys(crypto: &TempCryptoComponentGeneric<Csp, ReproducibleRng>) -> PublicKey {
            crypto
                .current_node_public_keys()
                .expect("Failed to retrieve current node public keys")
                .idkg_dealing_encryption_public_key
                .expect("Failed to retrieve IDKG encryption pubkey")
        }
        let initial_keys_0 = get_idkg_keys(&temp_crypto_0_rng_0);
        let initial_keys_1 = get_idkg_keys(&temp_crypto_1_rng_0);
        let initial_keys_2 = get_idkg_keys(&temp_crypto_2_rng_1);

        // TODO(CRP-2065): Compare all keys after replacing OpenSSL's time source in
        // certificate generation with vault's time source.

        // check (in)equality of initial iDKG keys for crypto components
        assert_eq!(initial_keys_0, initial_keys_1);
        assert_ne!(initial_keys_0, initial_keys_2);

        // rotate iDKG keys
        assert_matches!(
            temp_crypto_0_rng_0.rotate_idkg_dealing_encryption_keys(REG_V1),
            Ok(_)
        );
        assert_matches!(
            temp_crypto_1_rng_0.rotate_idkg_dealing_encryption_keys(REG_V1),
            Ok(_)
        );
        assert_matches!(
            temp_crypto_2_rng_1.rotate_idkg_dealing_encryption_keys(REG_V1),
            Ok(_)
        );

        let rotated_keys_0 = get_idkg_keys(&temp_crypto_0_rng_0);
        let rotated_keys_1 = get_idkg_keys(&temp_crypto_1_rng_0);
        let rotated_keys_2 = get_idkg_keys(&temp_crypto_2_rng_1);

        // check inequality of rotated iDKG keys and initial keys
        assert_ne!(initial_keys_0, rotated_keys_0);
        assert_ne!(initial_keys_1, rotated_keys_1);
        assert_ne!(initial_keys_2, rotated_keys_2);

        // check (in)equality of rotated iDKG keys for crypto components
        assert_eq!(rotated_keys_0, rotated_keys_1);
        assert_ne!(rotated_keys_0, rotated_keys_2);
    }
}
