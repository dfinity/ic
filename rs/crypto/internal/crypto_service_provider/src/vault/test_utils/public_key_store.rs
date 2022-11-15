use crate::keygen::utils::{
    committee_signing_pk_to_proto, dkg_dealing_encryption_pk_to_proto,
    idkg_dealing_encryption_pk_to_proto, node_signing_pk_to_proto,
};
use crate::vault::api::CspVault;
use ic_crypto_internal_threshold_sig_ecdsa::MEGaPublicKey;
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types_test_utils::ids::node_test_id;
use std::sync::Arc;

pub const NODE_1: u64 = 4241;
pub const FIXED_SEED: u64 = 42;
pub const NOT_AFTER: &str = "25670102030405Z";

pub fn should_retrieve_current_public_keys(csp_vault: Arc<dyn CspVault>) {
    let node_signing_public_key = csp_vault
        .gen_node_signing_key_pair()
        .expect("Could not generate node signing keys");
    let committee_signing_public_key = csp_vault
        .gen_committee_signing_key_pair()
        .expect("Could not generate committee signing keys");
    let cert = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");
    let (nidkg_public_key, nidkg_pop) = csp_vault
        .gen_forward_secure_key_pair(node_test_id(NODE_1), AlgorithmId::NiDkg_Groth20_Bls12_381)
        .expect("Failed to generate DKG dealing encryption keys");
    let idkg_public_key = generate_idkg_dealing_encryption_key_pair(&csp_vault);

    let current_public_keys = csp_vault
        .current_node_public_keys()
        .expect("Error retrieving current node public keys");

    assert_eq!(
        current_public_keys,
        CurrentNodePublicKeys {
            node_signing_public_key: Some(node_signing_pk_to_proto(node_signing_public_key)),
            committee_signing_public_key: Some(committee_signing_pk_to_proto(
                committee_signing_public_key
            )),
            tls_certificate: Some(cert.to_proto()),
            dkg_dealing_encryption_public_key: Some(dkg_dealing_encryption_pk_to_proto(
                nidkg_public_key,
                nidkg_pop
            )),
            idkg_dealing_encryption_public_key: Some(idkg_dealing_encryption_pk_to_proto(
                idkg_public_key
            ))
        }
    )
}

pub fn should_retrieve_last_idkg_public_key(csp_vault: Arc<dyn CspVault>) {
    let idkg_public_key_1 = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    assert_eq!(
        idkg_dealing_encryption_pk_to_proto(idkg_public_key_1.clone()),
        csp_vault
            .current_node_public_keys()
            .expect("Error retrieving current node public keys")
            .idkg_dealing_encryption_public_key
            .expect("missing iDKG key")
    );

    let idkg_public_key_2 = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    assert_ne!(idkg_public_key_1, idkg_public_key_2);
    assert_eq!(
        idkg_dealing_encryption_pk_to_proto(idkg_public_key_2),
        csp_vault
            .current_node_public_keys()
            .expect("Error retrieving current node public keys")
            .idkg_dealing_encryption_public_key
            .expect("missing iDKG key")
    );
}

fn generate_idkg_dealing_encryption_key_pair(csp_vault: &Arc<dyn CspVault>) -> MEGaPublicKey {
    csp_vault
        .idkg_gen_mega_key_pair(AlgorithmId::ThresholdEcdsaSecp256k1)
        .expect("Failed to generate IDkg dealing encryption keys")
}
