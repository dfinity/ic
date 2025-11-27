use crate::CspVault;
use crate::ExternalPublicKeys;
use crate::vault::api::IDkgProtocolCspVault;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::MEGaPublicKey;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types_test_utils::ids::node_test_id;

pub const NODE_1: u64 = 4241;

pub(crate) fn convert_to_external_public_keys(
    current_node_public_keys: CurrentNodePublicKeys,
) -> ExternalPublicKeys {
    ExternalPublicKeys {
        node_signing_public_key: current_node_public_keys
            .node_signing_public_key
            .expect("node signing public key missing"),
        committee_signing_public_key: current_node_public_keys
            .committee_signing_public_key
            .expect("committee signing public key missing"),
        tls_certificate: current_node_public_keys
            .tls_certificate
            .expect("tls certificate missing"),
        dkg_dealing_encryption_public_key: current_node_public_keys
            .dkg_dealing_encryption_public_key
            .expect("dkg dealing encryption public key missing"),
        idkg_dealing_encryption_public_key: current_node_public_keys
            .idkg_dealing_encryption_public_key
            .expect("idkg dealing encryption public key missing"),
    }
}

pub(crate) fn generate_idkg_dealing_encryption_key_pair<V: IDkgProtocolCspVault>(
    csp_vault: &V,
) -> MEGaPublicKey {
    csp_vault
        .idkg_gen_dealing_encryption_key_pair()
        .expect("Failed to generate IDkg dealing encryption keys")
}

pub(crate) fn generate_all_keys<V: CspVault>(csp_vault: &V) -> CurrentNodePublicKeys {
    let _node_signing_pk = csp_vault
        .gen_node_signing_key_pair()
        .expect("Failed to generate node signing key pair");
    let _committee_signing_pk = csp_vault
        .gen_committee_signing_key_pair()
        .expect("Failed to generate committee signing key pair");
    let _dkg_dealing_encryption_pk = csp_vault
        .gen_dealing_encryption_key_pair(node_test_id(NODE_1))
        .expect("Failed to generate NI-DKG dealing encryption key pair");
    let _tls_certificate = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1))
        .expect("Failed to generate TLS certificate");
    let _idkg_dealing_encryption_key = generate_idkg_dealing_encryption_key_pair(csp_vault);
    csp_vault
        .current_node_public_keys()
        .expect("Failed to get current node public keys")
}
