use assert_matches::assert_matches;

mod registry {
    use super::*;
    use crate::internal::{
        nns_root_public_key, registry_with_root_of_trust, DUMMY_REGISTRY_VERSION,
    };
    use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::crypto::CryptoRegistry;
    use ic_registry_client_helpers::subnet::SubnetRegistry;
    use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
    use ic_types::RegistryVersion;

    #[test]
    fn should_get_registry_with_nns_root_public_key() {
        let (registry_client, _registry_data) = registry_with_root_of_trust(nns_root_public_key());

        let retrieved_nns_root_public_key =
            crypto_logic_to_retrieve_root_subnet_pubkey(&registry_client, DUMMY_REGISTRY_VERSION);

        assert_matches!(retrieved_nns_root_public_key, Some(actual_key)
            if actual_key == nns_root_public_key());
    }

    #[test]
    fn should_get_registry_with_other_subnet_public_key() {
        let other_root_of_trust = parse_threshold_sig_key_from_der(&hex::decode("308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C05030201036100923A67B791270CD8F5320212AE224377CF407D3A8A2F44F11FED5915A97EE67AD0E90BC382A44A3F14C363AD2006640417B4BBB3A304B97088EC6B4FC87A25558494FC239B47E129260232F79973945253F5036FD520DDABD1E2DE57ABFB40CB").unwrap()).unwrap();
        let (registry_client, _registry_data) = registry_with_root_of_trust(other_root_of_trust);

        let retrieved_root_of_trust =
            crypto_logic_to_retrieve_root_subnet_pubkey(&registry_client, DUMMY_REGISTRY_VERSION);

        assert_matches!(retrieved_root_of_trust, Some(actual_key)
            if actual_key == other_root_of_trust);
    }

    fn crypto_logic_to_retrieve_root_subnet_pubkey(
        registry: &FakeRegistryClient,
        registry_version: RegistryVersion,
    ) -> Option<ThresholdSigPublicKey> {
        let root_subnet_id = registry
            .get_root_subnet_id(registry_version)
            .expect("error retrieving root subnet ID")
            .expect("missing root subnet ID");
        registry
            .get_threshold_signing_public_key_for_subnet(root_subnet_id, registry_version)
            .expect("error retrieving root public key")
    }
}
