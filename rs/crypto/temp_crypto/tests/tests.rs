use ic_config::crypto::CryptoConfig;
use ic_crypto_temp_crypto::{TempCryptoComponent, TempCryptoComponentGeneric};
use ic_crypto_test_utils::empty_fake_registry;
use ic_interfaces::crypto::CurrentNodePublicKeysError;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types_test_utils::ids::node_test_id;
use rand_chacha::ChaCha20Rng;
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
    assert!(result.is_ok(), "{result:?}");
}

mod vault_rng {
    use super::*;
    use assert_matches::assert_matches;
    use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
    use ic_crypto_temp_crypto::{EcdsaSubnetConfig, NodeKeysToGenerate};
    use ic_interfaces::crypto::KeyManager;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_time::FastForwardTimeSource;
    use rand::SeedableRng;
    use std::time::Duration;

    const TWO_WEEKS: Duration = Duration::from_secs(2 * 7 * 24 * 60 * 60);
    const REG_V1: RegistryVersion = RegistryVersion::new(1);
    const SUBNET_ID: SubnetId = SubnetId::new(PrincipalId::new(29, [0xfc; 29]));

    const SEED_0: [u8; 32] = [0u8; 32];
    const SEED_1: [u8; 32] = [1u8; 32];

    #[test]
    fn should_have_same_initial_keys_with_same_rng() {
        for set_remote_vault in [true, false] {
            println!("Running tests for remote vault: {set_remote_vault}");
            let crypto_0 = new_idkg_crypto_with_rng_and_opt_remote_vault(
                ChaCha20Rng::from_seed(SEED_0),
                set_remote_vault,
            );
            let crypto_1 = new_idkg_crypto_with_rng_and_opt_remote_vault(
                ChaCha20Rng::from_seed(SEED_0),
                set_remote_vault,
            );

            assert_eq!(
                crypto_0.current_node_public_keys(),
                crypto_1.current_node_public_keys()
            );
        }
    }

    #[test]
    fn should_have_different_initial_keys_with_different_rng() {
        for set_remote_vault in [true, false] {
            println!("Running tests for remote vault: {set_remote_vault}");
            let crypto_0 = new_idkg_crypto_with_rng_and_opt_remote_vault(
                ChaCha20Rng::from_seed(SEED_0),
                set_remote_vault,
            );
            let crypto_1 = new_idkg_crypto_with_rng_and_opt_remote_vault(
                ChaCha20Rng::from_seed(SEED_1),
                set_remote_vault,
            );

            assert_ne_each_key(
                crypto_0.current_node_public_keys(),
                crypto_1.current_node_public_keys(),
            );
        }
    }

    #[test]
    fn should_have_same_rotated_keys_with_same_rng() {
        for set_remote_vault in [true, false] {
            println!("Running tests for remote vault: {set_remote_vault}");
            let crypto_0 = new_idkg_crypto_with_rng_and_opt_remote_vault(
                ChaCha20Rng::from_seed(SEED_0),
                set_remote_vault,
            );
            let crypto_1 = new_idkg_crypto_with_rng_and_opt_remote_vault(
                ChaCha20Rng::from_seed(SEED_0),
                set_remote_vault,
            );

            assert_matches!(crypto_0.rotate_idkg_dealing_encryption_keys(REG_V1), Ok(_));
            assert_matches!(crypto_1.rotate_idkg_dealing_encryption_keys(REG_V1), Ok(_));

            let rotated_keys_0 = crypto_0.current_node_public_keys();
            let rotated_keys_1 = crypto_1.current_node_public_keys();

            assert_eq!(rotated_keys_0, rotated_keys_1);
        }
    }

    #[test]
    fn should_have_different_rotated_keys_with_different_rng() {
        for set_remote_vault in [true, false] {
            println!("Running tests for remote vault: {set_remote_vault}");
            let crypto_0 = new_idkg_crypto_with_rng_and_opt_remote_vault(
                ChaCha20Rng::from_seed(SEED_0),
                set_remote_vault,
            );
            let crypto_1 = new_idkg_crypto_with_rng_and_opt_remote_vault(
                ChaCha20Rng::from_seed(SEED_1),
                set_remote_vault,
            );

            // rotate iDKG keys
            assert_matches!(crypto_0.rotate_idkg_dealing_encryption_keys(REG_V1), Ok(_));
            assert_matches!(crypto_1.rotate_idkg_dealing_encryption_keys(REG_V1), Ok(_));

            let rotated_keys_0 = crypto_0.current_node_public_keys();
            let rotated_keys_1 = crypto_1.current_node_public_keys();

            assert_ne_each_key(rotated_keys_0, rotated_keys_1);
        }
    }

    fn new_idkg_crypto_with_rng_and_opt_remote_vault(
        rng: ChaCha20Rng,
        with_remote_vault: bool,
    ) -> TempCryptoComponentGeneric<ChaCha20Rng> {
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

    fn assert_ne_each_key(
        lhs: Result<CurrentNodePublicKeys, CurrentNodePublicKeysError>,
        rhs: Result<CurrentNodePublicKeys, CurrentNodePublicKeysError>,
    ) {
        let CurrentNodePublicKeys {
            node_signing_public_key: l_ns_pk,
            committee_signing_public_key: l_cs_pk,
            tls_certificate: l_tls_cert,
            dkg_dealing_encryption_public_key: l_dkg_de_pk,
            idkg_dealing_encryption_public_key: l_idkg_de_pk,
        } = lhs.expect("failed to retrieve current node public keys");

        let CurrentNodePublicKeys {
            node_signing_public_key: r_ns_pk,
            committee_signing_public_key: r_cs_pk,
            tls_certificate: r_tls_cert,
            dkg_dealing_encryption_public_key: r_dkg_de_pk,
            idkg_dealing_encryption_public_key: r_idkg_de_pk,
        } = rhs.expect("failed to retrieve current node public keys");

        assert_matches!((l_ns_pk, r_ns_pk), (Some(l_pk), Some(r_pk)) if l_pk.key_value != r_pk.key_value);
        assert_matches!((l_cs_pk, r_cs_pk), (Some(l_pk), Some(r_pk)) if l_pk.key_value != r_pk.key_value);
        assert_ne!(
            l_tls_cert.expect("failed to obtain cert"),
            r_tls_cert.expect("failed to obtain cert")
        );
        assert_matches!((l_dkg_de_pk, r_dkg_de_pk), (Some(l_pk), Some(r_pk)) if l_pk.key_value != r_pk.key_value);
        assert_matches!((l_idkg_de_pk, r_idkg_de_pk), (Some(l_pk), Some(r_pk)) if l_pk.key_value != r_pk.key_value);
    }
}
