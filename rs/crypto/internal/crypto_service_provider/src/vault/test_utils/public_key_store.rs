use crate::keygen::utils::{
    committee_signing_pk_to_proto, dkg_dealing_encryption_pk_to_proto,
    idkg_dealing_encryption_pk_to_proto, node_signing_pk_to_proto,
};
use crate::vault::api::CspVault;
use assert_matches::assert_matches;
use ic_crypto_internal_threshold_sig_ecdsa::MEGaPublicKey;
use ic_protobuf::registry::crypto::v1::{PublicKey, X509PublicKeyCert};
use ic_test_utilities::FastForwardTimeSource;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types::time::GENESIS;
use ic_types::Time;
use ic_types_test_utils::ids::node_test_id;
use std::sync::Arc;

pub const NODE_1: u64 = 4241;
pub const FIXED_SEED: u64 = 42;
pub const NOT_AFTER: &str = "99991231235959Z";

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
        .gen_dealing_encryption_key_pair(node_test_id(NODE_1))
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

pub fn should_be_consistent_with_current_node_public_keys(csp_vault: Arc<dyn CspVault>) {
    let _ = generate_all_keys(&csp_vault);

    let current_public_keys_with_timestamps = csp_vault
        .current_node_public_keys_with_timestamps()
        .expect("Error retrieving current node public keys with timestamps");
    let current_public_keys = csp_vault
        .current_node_public_keys()
        .expect("Error retrieving current node public keys");

    assert!(equal_ignoring_timestamp(
        &current_public_keys_with_timestamps,
        &current_public_keys
    ));
}

pub fn should_retrieve_timestamp_of_generated_idkg_public_key(
    csp_vault: Arc<dyn CspVault>,
    expected_generation_timestamp: Time,
) {
    let generated_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);

    let retrieved_idkg_pk_with_timestamp = csp_vault
        .current_node_public_keys_with_timestamps()
        .expect("Failed to retrieve current node public keys")
        .idkg_dealing_encryption_public_key
        .expect("missing IDKG dealing encryption public key");

    assert!(retrieved_idkg_pk_with_timestamp
        .equal_ignoring_timestamp(&idkg_dealing_encryption_pk_to_proto(generated_idkg_pk)));
    assert_matches!(
        retrieved_idkg_pk_with_timestamp.timestamp,
        Some(time) if time == expected_generation_timestamp.as_millis_since_unix_epoch()
    );
}

//TODO CRP-1857: modify this test as needed when timestamp are introduced upon key generation for non-IDKG keys
pub fn should_not_retrieve_timestamps_of_other_generated_keys_because_they_are_not_set_yet(
    csp_vault: Arc<dyn CspVault>,
) {
    let _ = generate_all_keys(&csp_vault);

    let pks_with_timestamps = csp_vault
        .current_node_public_keys_with_timestamps()
        .expect("Failed to retrieve current node public keys");

    assert_matches!(pks_with_timestamps.node_signing_public_key, Some(pk) if pk.timestamp.is_none());
    assert_matches!(pks_with_timestamps.committee_signing_public_key, Some(pk) if pk.timestamp.is_none());
    assert_matches!(pks_with_timestamps.dkg_dealing_encryption_public_key, Some(pk) if pk.timestamp.is_none());
}

pub fn genesis_time_source() -> Arc<FastForwardTimeSource> {
    let time_source = FastForwardTimeSource::new();
    time_source.set_time(GENESIS).expect("wrong time");
    time_source
}

pub fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_no_keys(
    csp_vault: Arc<dyn CspVault>,
) {
    let result = csp_vault
        .idkg_dealing_encryption_pubkeys_count()
        .expect("Error calling idkg_key_count");
    assert_eq!(0, result);
}

pub fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_single_key(
    csp_vault: Arc<dyn CspVault>,
) {
    let _initial_node_public_keys = generate_all_keys(&csp_vault);
    let result = csp_vault
        .idkg_dealing_encryption_pubkeys_count()
        .expect("Error calling idkg_key_count");
    assert_eq!(1, result);
}

pub fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_two_keys(
    csp_vault: Arc<dyn CspVault>,
) {
    let _initial_node_public_keys = generate_all_keys(&csp_vault);
    let _second_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    let result = csp_vault
        .idkg_dealing_encryption_pubkeys_count()
        .expect("Error calling idkg_key_count");
    assert_eq!(2, result);
}

pub fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_when_all_other_keys_exist_except_idkg_key(
    csp_vault: Arc<dyn CspVault>,
) {
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
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Failed to generate TLS certificate");

    let result = csp_vault
        .idkg_dealing_encryption_pubkeys_count()
        .expect("Error calling idkg_key_count");
    assert_eq!(0, result);
}

pub(crate) fn generate_idkg_dealing_encryption_key_pair(
    csp_vault: &Arc<dyn CspVault>,
) -> MEGaPublicKey {
    csp_vault
        .idkg_gen_dealing_encryption_key_pair()
        .expect("Failed to generate IDkg dealing encryption keys")
}

pub(crate) fn generate_all_keys(csp_vault: &Arc<dyn CspVault>) -> CurrentNodePublicKeys {
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
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Failed to generate TLS certificate");
    let _idkg_dealing_encryption_key = generate_idkg_dealing_encryption_key_pair(csp_vault);
    csp_vault
        .current_node_public_keys()
        .expect("Failed to get current node public keys")
}

fn equal_ignoring_timestamp(left: &CurrentNodePublicKeys, right: &CurrentNodePublicKeys) -> bool {
    equal_ignoring_timestamp_option(
        &left.node_signing_public_key,
        &right.node_signing_public_key,
    ) && equal_ignoring_timestamp_option(
        &left.committee_signing_public_key,
        &right.committee_signing_public_key,
    ) && left.tls_certificate == right.tls_certificate
        && equal_ignoring_timestamp_option(
            &left.dkg_dealing_encryption_public_key,
            &right.dkg_dealing_encryption_public_key,
        )
        && equal_ignoring_timestamp_option(
            &left.idkg_dealing_encryption_public_key,
            &right.idkg_dealing_encryption_public_key,
        )
}

fn equal_ignoring_timestamp_option(left: &Option<PublicKey>, right: &Option<PublicKey>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(_), None) => false,
        (None, Some(_)) => false,
        (Some(left_pk), Some(right_pk)) => left_pk.equal_ignoring_timestamp(right_pk),
    }
}

#[test]
fn should_current_node_public_keys_be_equal_ignoring_timestamp() {
    //If you need to modify this test because for example the struct CurrentNodePublicKeys changed,
    //also modify the method equal_ignoring_timestamp!
    let public_keys = CurrentNodePublicKeys {
        node_signing_public_key: Some(public_key_with_key_value(1)),
        committee_signing_public_key: Some(public_key_with_key_value(2)),
        tls_certificate: Some(public_key_certificate_with_der(1)),
        dkg_dealing_encryption_public_key: Some(public_key_with_key_value(3)),
        idkg_dealing_encryption_public_key: Some(public_key_with_key_value(4)),
    };

    assert!(equal_ignoring_timestamp(&public_keys, &public_keys));

    let mut other_public_keys = public_keys.clone();
    other_public_keys.tls_certificate = Some(public_key_certificate_with_der(2));
    assert!(!equal_ignoring_timestamp(&public_keys, &other_public_keys));
}

fn public_key_with_key_value(key_value: u8) -> PublicKey {
    use ic_types::crypto::AlgorithmId;
    PublicKey {
        version: 1,
        algorithm: AlgorithmId::Ed25519 as i32,
        key_value: [key_value; 10].to_vec(),
        proof_data: None,
        timestamp: None,
    }
}

fn public_key_certificate_with_der(certificate_der: u8) -> X509PublicKeyCert {
    X509PublicKeyCert {
        certificate_der: [certificate_der; 10].to_vec(),
    }
}
