use super::*;
use assert_matches::assert_matches;
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::generate_node_keys_once;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_test_utils_ni_dkg::{initial_dkg_transcript_and_master_key, InitialNiDkgConfig};
use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
use ic_crypto_utils_ni_dkg::extract_threshold_sig_public_key;
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::registry::new_current_node_crypto_keys_mutations;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::subnet::v1::{
    CatchUpPackageContents, InitialNiDkgTranscriptRecord, SubnetListRecord,
};
use ic_registry_keys::make_catch_up_package_contents_key;
use ic_registry_keys::{make_node_record_key, make_subnet_list_record_key};
use ic_registry_transport::insert;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTargetId, NiDkgTranscript};
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types::RegistryVersion;
use ic_types_test_utils::ids::{SUBNET_1, SUBNET_2};
use rand::RngCore;
use std::collections::BTreeSet;

fn insert_node_crypto_keys(
    node_id: &NodeId,
    node_pks: CurrentNodePublicKeys,
    snapshot: &mut RegistrySnapshot,
) {
    let mutations = new_current_node_crypto_keys_mutations(*node_id, node_pks);
    for m in mutations {
        snapshot.insert(m.key, m.value);
    }
}

fn valid_node_keys_and_node_id() -> (CurrentNodePublicKeys, NodeId) {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let node_pks =
        generate_node_keys_once(&config, None).expect("error generating node public keys");
    let node_id = node_pks.node_id();
    (map_to_current_node_public_keys(node_pks), node_id)
}

fn map_to_current_node_public_keys(value: ValidNodePublicKeys) -> CurrentNodePublicKeys {
    CurrentNodePublicKeys {
        node_signing_public_key: Some(value.node_signing_key().clone()),
        committee_signing_public_key: Some(value.committee_signing_key().clone()),
        tls_certificate: Some(value.tls_certificate().clone()),
        dkg_dealing_encryption_public_key: Some(value.dkg_dealing_encryption_key().clone()),
        idkg_dealing_encryption_public_key: Some(value.idkg_dealing_encryption_key().clone()),
    }
}

fn insert_dummy_node(node_id: &NodeId, snapshot: &mut RegistrySnapshot) {
    snapshot.insert(
        make_node_record_key(node_id.to_owned()).into_bytes(),
        encode_or_panic::<NodeRecord>(&NodeRecord::default()),
    );
}

#[test]
fn node_crypto_keys_invariants_valid_snapshot() {
    // Crypto keys for the test.
    let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
    let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

    // Generate and check a valid snapshot.
    let mut snapshot = RegistrySnapshot::new();
    insert_dummy_node(&node_id_1, &mut snapshot);
    insert_dummy_node(&node_id_2, &mut snapshot);
    insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);
    insert_node_crypto_keys(&node_id_2, node_pks_2, &mut snapshot);
    assert!(check_node_crypto_keys_invariants(&snapshot).is_ok());
}

// TODO(CRP-1450): add tests for "missing" "invalid", and "duplicated" scenarios, so that
//   these scenarios are tested for all 5 keys of a node.
#[test]
fn node_crypto_keys_invariants_missing_committee_key() {
    // Crypto keys for the test.
    let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
    let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

    // Generate and check a valid snapshot.
    let mut snapshot = RegistrySnapshot::new();
    insert_dummy_node(&node_id_1, &mut snapshot);
    insert_dummy_node(&node_id_2, &mut snapshot);
    insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);

    let incomplete_node_public_keys = CurrentNodePublicKeys {
        committee_signing_public_key: None,
        ..node_pks_2
    };
    insert_node_crypto_keys(&node_id_2, incomplete_node_public_keys, &mut snapshot);
    let result = check_node_crypto_keys_invariants(&snapshot);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&node_id_2.to_string()));
    assert!(err.to_string().contains("has no key"));
    assert!(err.to_string().contains("CommitteeSigning"));
}

#[test]
fn node_crypto_keys_invariants_missing_node_signing_key() {
    // Crypto keys for the test.
    let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
    let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

    // Generate and check a valid snapshot.
    let mut snapshot = RegistrySnapshot::new();
    insert_dummy_node(&node_id_1, &mut snapshot);
    insert_dummy_node(&node_id_2, &mut snapshot);
    insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);

    let incomplete_node_public_keys = CurrentNodePublicKeys {
        node_signing_public_key: None,
        ..node_pks_2
    };
    insert_node_crypto_keys(&node_id_2, incomplete_node_public_keys, &mut snapshot);
    let result = check_node_crypto_keys_invariants(&snapshot);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&node_id_2.to_string()));
    assert!(err.to_string().contains("has no key"));
    assert!(err.to_string().contains("NodeSigning"));
}

#[test]
fn node_crypto_keys_invariants_missing_idkg_dealing_encryption_key() {
    // Crypto keys for the test.
    let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
    let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

    // Generate and check a valid snapshot.
    let mut snapshot = RegistrySnapshot::new();
    insert_dummy_node(&node_id_1, &mut snapshot);
    insert_dummy_node(&node_id_2, &mut snapshot);
    insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);

    let incomplete_node_public_keys = CurrentNodePublicKeys {
        idkg_dealing_encryption_public_key: None,
        ..node_pks_2
    };
    insert_node_crypto_keys(&node_id_2, incomplete_node_public_keys, &mut snapshot);
    let result = check_node_crypto_keys_invariants(&snapshot);

    assert_matches!(result,
                    Err(InvariantCheckError{msg: error_message, source: _})
            if error_message.contains("has no key for purpose IDkgMEGaEncryption"));
}

#[test]
fn node_crypto_keys_invariants_missing_tls_cert() {
    // Crypto keys for the test.
    let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
    let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

    // Generate and check a valid snapshot.
    let mut snapshot = RegistrySnapshot::new();
    insert_dummy_node(&node_id_1, &mut snapshot);
    insert_dummy_node(&node_id_2, &mut snapshot);
    insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);

    let incomplete_node_public_keys = CurrentNodePublicKeys {
        tls_certificate: None,
        ..node_pks_2
    };
    insert_node_crypto_keys(&node_id_2, incomplete_node_public_keys, &mut snapshot);
    let result = check_node_crypto_keys_invariants(&snapshot);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&node_id_2.to_string()));
    assert!(err.to_string().contains("has no TLS cert"));
}

#[test]
fn node_crypto_keys_invariants_duplicated_committee_key() {
    // Crypto keys for the test.
    let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
    let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

    // Generate and check a valid snapshot.
    let mut snapshot = RegistrySnapshot::new();
    insert_dummy_node(&node_id_1, &mut snapshot);
    insert_dummy_node(&node_id_2, &mut snapshot);
    insert_node_crypto_keys(&node_id_1, node_pks_1.clone(), &mut snapshot);

    let duplicated_key_node_pks = CurrentNodePublicKeys {
        committee_signing_public_key: node_pks_1.committee_signing_public_key,
        ..node_pks_2
    };
    insert_node_crypto_keys(&node_id_2, duplicated_key_node_pks, &mut snapshot);
    let result = check_node_crypto_keys_invariants(&snapshot);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&node_id_1.to_string()));
    assert!(err.to_string().contains(&node_id_2.to_string()));
    assert!(err.to_string().contains("the same public key"));
}

#[test]
fn node_crypto_keys_invariants_duplicated_idkg_encryption_key() {
    // Crypto keys for the test.
    let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
    let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

    // Generate and check a valid snapshot.
    let mut snapshot = RegistrySnapshot::new();
    insert_dummy_node(&node_id_1, &mut snapshot);
    insert_dummy_node(&node_id_2, &mut snapshot);
    insert_node_crypto_keys(&node_id_1, node_pks_1.clone(), &mut snapshot);

    let duplicated_key_node_pks = CurrentNodePublicKeys {
        idkg_dealing_encryption_public_key: node_pks_1.idkg_dealing_encryption_public_key,
        ..node_pks_2
    };
    insert_node_crypto_keys(&node_id_2, duplicated_key_node_pks, &mut snapshot);
    let result = check_node_crypto_keys_invariants(&snapshot);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&node_id_1.to_string()));
    assert!(err.to_string().contains(&node_id_2.to_string()));
    assert!(err.to_string().contains("the same public key"));
}

#[test]
fn node_crypto_keys_invariants_duplicated_tls_cert() {
    // Crypto keys for the test.
    let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
    let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

    // Generate and check a valid snapshot.
    let mut snapshot = RegistrySnapshot::new();
    insert_dummy_node(&node_id_1, &mut snapshot);
    insert_dummy_node(&node_id_2, &mut snapshot);
    insert_node_crypto_keys(&node_id_1, node_pks_1.clone(), &mut snapshot);

    let duplicated_cert_node_pks = CurrentNodePublicKeys {
        tls_certificate: node_pks_1.tls_certificate,
        ..node_pks_2
    };
    insert_node_crypto_keys(&node_id_2, duplicated_cert_node_pks, &mut snapshot);
    let result = check_node_crypto_keys_invariants(&snapshot);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&node_id_1.to_string()));
    assert!(err.to_string().contains(&node_id_2.to_string()));
    assert!(err.to_string().contains("use the same certificate"));
}

#[test]
fn node_crypto_keys_invariants_inconsistent_node_id() {
    // Crypto keys for the test.
    let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
    let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

    // Generate and check a valid snapshot.
    let mut snapshot = RegistrySnapshot::new();
    insert_dummy_node(&node_id_1, &mut snapshot);
    insert_dummy_node(&node_id_2, &mut snapshot);
    insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);

    let (node_pks_3, _node_id_3) = valid_node_keys_and_node_id();
    let inconsistent_signing_key_node_pks = CurrentNodePublicKeys {
        node_signing_public_key: node_pks_3.node_signing_public_key,
        ..node_pks_2
    };
    insert_node_crypto_keys(&node_id_2, inconsistent_signing_key_node_pks, &mut snapshot);
    let result = check_node_crypto_keys_invariants(&snapshot);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&node_id_2.to_string()));
    assert!(err.to_string().contains("inconsistent NodeSigning key"));
}

#[test]
fn orphaned_crypto_node_signing_pk() {
    let (mut orphaned_keys, missing_node) = valid_node_keys_and_node_id();
    // This leaves only node_signing_pk as orphan.
    orphaned_keys.committee_signing_public_key = None;
    orphaned_keys.tls_certificate = None;
    orphaned_keys.dkg_dealing_encryption_public_key = None;
    orphaned_keys.idkg_dealing_encryption_public_key = None;
    run_test_orphaned_crypto_keys(missing_node, orphaned_keys);
}

#[test]
fn orphaned_crypto_committee_signing_pk() {
    let (mut orphaned_keys, missing_node) = valid_node_keys_and_node_id();
    orphaned_keys.node_signing_public_key = None;
    // This leaves only committee_signing_pk as orphan.
    orphaned_keys.tls_certificate = None;
    orphaned_keys.dkg_dealing_encryption_public_key = None;
    orphaned_keys.idkg_dealing_encryption_public_key = None;
    run_test_orphaned_crypto_keys(missing_node, orphaned_keys);
}

#[test]
fn orphaned_crypto_tls_certificate() {
    let (mut orphaned_keys, missing_node) = valid_node_keys_and_node_id();
    orphaned_keys.node_signing_public_key = None;
    orphaned_keys.committee_signing_public_key = None;
    // This leaves only tls_certificate as orphan.
    orphaned_keys.dkg_dealing_encryption_public_key = None;
    orphaned_keys.idkg_dealing_encryption_public_key = None;
    run_test_orphaned_crypto_keys(missing_node, orphaned_keys);
}

#[test]
fn orphaned_crypto_dkg_dealing_encryption_pk() {
    let (mut orphaned_keys, missing_node) = valid_node_keys_and_node_id();
    orphaned_keys.node_signing_public_key = None;
    orphaned_keys.committee_signing_public_key = None;
    orphaned_keys.tls_certificate = None;
    // This leaves only dkg_dealing_encryption_pk as orphan.
    orphaned_keys.idkg_dealing_encryption_public_key = None;
    run_test_orphaned_crypto_keys(missing_node, orphaned_keys);
}

#[test]
fn orphaned_crypto_idkg_dealing_encryption_pk() {
    let (mut orphaned_keys, missing_node) = valid_node_keys_and_node_id();
    orphaned_keys.node_signing_public_key = None;
    orphaned_keys.committee_signing_public_key = None;
    orphaned_keys.tls_certificate = None;
    orphaned_keys.dkg_dealing_encryption_public_key = None;
    // This leaves only idkg_dealing_encryption_pk as orphan.
    run_test_orphaned_crypto_keys(missing_node, orphaned_keys);
}

const REG_V1: RegistryVersion = RegistryVersion::new(1);

#[test]
fn high_threshold_public_key_invariant_valid_snapshot() {
    let setup = HighThresholdPublicKeySetup::new();
    let snapshot = registry_snapshot_from_threshold_sig_pk_and_cup(
        Some(setup.threshold_sig_pk),
        Some(setup.cup_contents),
        setup.receiver_subnet,
    );

    assert!(check_high_threshold_public_key_matches_the_one_in_cup(&snapshot).is_ok());
}

#[test]
fn high_threshold_public_key_invariant_public_key_mismatch() {
    let setup = HighThresholdPublicKeySetup::new();
    let threshold_sig_pk = corrupt_threshold_sig_pk(setup.threshold_sig_pk);
    let snapshot = registry_snapshot_from_threshold_sig_pk_and_cup(
        Some(threshold_sig_pk),
        Some(setup.cup_contents),
        setup.receiver_subnet,
    );

    assert!(check_high_threshold_public_key_matches_the_one_in_cup(&snapshot).is_err());
}

#[test]
fn high_threshold_public_key_invariant_missing_public_key() {
    let setup = HighThresholdPublicKeySetup::new();
    let snapshot = registry_snapshot_from_threshold_sig_pk_and_cup(
        None,
        Some(setup.cup_contents),
        setup.receiver_subnet,
    );

    assert!(check_high_threshold_public_key_matches_the_one_in_cup(&snapshot).is_err());
}

#[test]
fn high_threshold_public_key_invariant_missing_cup() {
    let setup = HighThresholdPublicKeySetup::new();
    let snapshot = registry_snapshot_from_threshold_sig_pk_and_cup(
        Some(setup.threshold_sig_pk),
        None,
        setup.receiver_subnet,
    );

    assert!(check_high_threshold_public_key_matches_the_one_in_cup(&snapshot).is_err());
}

#[test]
fn high_threshold_public_key_invariant_public_key_and_cup_both_missing() {
    let subnet_list_record = SubnetListRecord {
        subnets: vec![SUBNET_1.get().into_vec(), SUBNET_2.get().into_vec()],
    };
    let subnet_list_record_key = make_subnet_list_record_key();
    let subnet_mutation = insert(
        subnet_list_record_key.into_bytes(),
        encode_or_panic(&subnet_list_record),
    );
    let mut snapshot = RegistrySnapshot::new();
    snapshot.insert(subnet_mutation.key, subnet_mutation.value);

    assert!(check_high_threshold_public_key_matches_the_one_in_cup(&snapshot).is_err());
}

#[test]
fn high_threshold_public_key_invariant_unable_to_parse_key() {
    let setup = HighThresholdPublicKeySetup::new();
    let mut snapshot = registry_snapshot_from_threshold_sig_pk_and_cup(
        None,
        Some(setup.cup_contents),
        setup.receiver_subnet,
    );
    let pubkey_key = make_crypto_threshold_signing_pubkey_key(setup.receiver_subnet);
    let bad_pubkey_bytes = vec![];
    let pubkey_value = encode_or_panic(&bad_pubkey_bytes);
    let pubkey_mutation = insert(pubkey_key.into_bytes(), pubkey_value);
    snapshot.insert(pubkey_mutation.key, pubkey_mutation.value);

    assert!(check_high_threshold_public_key_matches_the_one_in_cup(&snapshot).is_err());
}

#[test]
fn high_threshold_public_key_invariant_unable_to_parse_cup() {
    let setup = HighThresholdPublicKeySetup::new();
    let mut snapshot = registry_snapshot_from_threshold_sig_pk_and_cup(
        Some(setup.threshold_sig_pk),
        None,
        setup.receiver_subnet,
    );
    let cup_contents_key = make_catch_up_package_contents_key(setup.receiver_subnet).into_bytes();
    let bad_cup_contents_bytes = vec![];
    let cup_mutation = insert(cup_contents_key, encode_or_panic(&bad_cup_contents_bytes));
    snapshot.insert(cup_mutation.key, cup_mutation.value);

    assert!(check_high_threshold_public_key_matches_the_one_in_cup(&snapshot).is_err());
}

#[test]
fn high_threshold_public_key_invariant_unable_to_parse_initial_ni_dkg_transcript_high_threshold_in_cup(
) {
    let mut setup = HighThresholdPublicKeySetup::new();
    let mut snapshot = registry_snapshot_from_threshold_sig_pk_and_cup(
        Some(setup.threshold_sig_pk),
        None,
        setup.receiver_subnet,
    );
    if let Some(mut initial_ni_dkg_transcript_high_threshold) =
        setup.cup_contents.initial_ni_dkg_transcript_high_threshold
    {
        initial_ni_dkg_transcript_high_threshold.internal_csp_transcript = vec![];
        setup.cup_contents.initial_ni_dkg_transcript_high_threshold =
            Some(initial_ni_dkg_transcript_high_threshold);
    }
    let cup_contents_key = make_catch_up_package_contents_key(setup.receiver_subnet).into_bytes();
    let cup_mutation = insert(cup_contents_key, encode_or_panic(&setup.cup_contents));
    snapshot.insert(cup_mutation.key, cup_mutation.value);

    assert!(check_high_threshold_public_key_matches_the_one_in_cup(&snapshot).is_err());
}

struct HighThresholdPublicKeySetup {
    receiver_subnet: SubnetId,
    threshold_sig_pk: ThresholdSigPublicKey,
    cup_contents: CatchUpPackageContents,
}

impl HighThresholdPublicKeySetup {
    fn new() -> Self {
        let dealer_subnet = SUBNET_1;
        let receiver_subnet = SUBNET_2;
        let rng = &mut reproducible_rng();
        let transcript =
            initial_dkg_transcript(REG_V1, dealer_subnet, NiDkgTag::HighThreshold, 2, rng);
        let (threshold_sig_pk, cup_contents) =
            subnet_threshold_sig_pubkey_and_cup_from_transcript(transcript);
        Self {
            receiver_subnet,
            threshold_sig_pk,
            cup_contents,
        }
    }
}

fn corrupt_threshold_sig_pk(threshold_sig_pk: ThresholdSigPublicKey) -> ThresholdSigPublicKey {
    let mut pubkey_proto = PublicKey::from(threshold_sig_pk);
    pubkey_proto.key_value[0] ^= 1;
    ThresholdSigPublicKey::try_from(pubkey_proto)
        .expect("error converting PublicKey back to ThresholdSigPublicKey")
}

fn generate_node_keys(num_nodes: usize) -> BTreeMap<NodeId, PublicKey> {
    let mut node_keys = BTreeMap::new();
    for _ in 0..num_nodes {
        let (node_pks, node_id) = valid_node_keys_and_node_id();
        let dkg_dealing_encryption_public_key = node_pks
            .dkg_dealing_encryption_public_key
            .as_ref()
            .expect("should have a dkg dealing encryption pk")
            .clone();
        node_keys.insert(node_id, dkg_dealing_encryption_public_key);
    }
    node_keys
}

fn initial_dkg_transcript(
    registry_version: RegistryVersion,
    dealer_subnet_id: SubnetId,
    dkg_tag: NiDkgTag,
    num_nodes: usize,
    rng: &mut ReproducibleRng,
) -> NiDkgTranscript {
    let mut target_id_bytes = [0u8; 32];
    rng.fill_bytes(&mut target_id_bytes);
    let target_id = NiDkgTargetId::new(target_id_bytes);
    let receiver_keys = generate_node_keys(num_nodes);
    let nodes_set: BTreeSet<NodeId> = receiver_keys.keys().cloned().collect();
    let config = InitialNiDkgConfig::new(
        &nodes_set,
        dealer_subnet_id,
        dkg_tag,
        target_id,
        registry_version,
    );
    let (transcript, _secret) = initial_dkg_transcript_and_master_key(config, &receiver_keys, rng);
    transcript
}

fn registry_snapshot_from_threshold_sig_pk_and_cup(
    threshold_sig_pk: Option<ThresholdSigPublicKey>,
    cup_contents: Option<CatchUpPackageContents>,
    receiver_subnet: SubnetId,
) -> RegistrySnapshot {
    let mut snapshot = RegistrySnapshot::new();
    if let Some(cup_contents) = cup_contents {
        let cup_contents_key = make_catch_up_package_contents_key(receiver_subnet).into_bytes();
        let cup_mutation = insert(cup_contents_key, encode_or_panic(&cup_contents));
        snapshot.insert(cup_mutation.key, cup_mutation.value);
    }
    let subnet_list_record = SubnetListRecord {
        subnets: vec![receiver_subnet.get().into_vec()],
    };
    let subnet_list_record_key = make_subnet_list_record_key();
    let subnet_mutation = insert(
        subnet_list_record_key.into_bytes(),
        encode_or_panic(&subnet_list_record),
    );
    snapshot.insert(subnet_mutation.key, subnet_mutation.value);
    if let Some(threshold_sig_pk) = threshold_sig_pk {
        let pubkey_key = make_crypto_threshold_signing_pubkey_key(receiver_subnet);
        let pubkey_proto = PublicKey::from(threshold_sig_pk);
        let pubkey_value = encode_or_panic(&pubkey_proto);
        let pubkey_mutation = insert(pubkey_key.into_bytes(), pubkey_value);
        snapshot.insert(pubkey_mutation.key, pubkey_mutation.value);
    }
    snapshot
}

fn subnet_threshold_sig_pubkey_and_cup_from_transcript(
    transcript: NiDkgTranscript,
) -> (ThresholdSigPublicKey, CatchUpPackageContents) {
    let threshold_sig_pk = extract_threshold_sig_public_key(&transcript.internal_csp_transcript)
        .expect("error extracting threshold sig public key from internal CSP transcript");
    let cup_contents = CatchUpPackageContents {
        initial_ni_dkg_transcript_high_threshold: Some(InitialNiDkgTranscriptRecord::from(
            transcript,
        )),
        ..Default::default()
    };
    (threshold_sig_pk, cup_contents)
}

/// Ensures that if there are any missing keys, the InvariantCheck is triggered for the 'missing_node_id', which
/// is not given an entry in the nodes table but will have the public_key records created for it
/// This is useful so that we can run the same test on each individual missing key
fn run_test_orphaned_crypto_keys(
    missing_node_id: NodeId,
    node_pks_with_missing_entries: CurrentNodePublicKeys,
) {
    // Crypto keys for the test.
    let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();

    // Generate and check a valid snapshot.
    let mut snapshot = RegistrySnapshot::new();
    insert_dummy_node(&node_id_1, &mut snapshot);
    insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);
    insert_node_crypto_keys(
        &missing_node_id,
        node_pks_with_missing_entries,
        &mut snapshot,
    );

    // TODO make this test more robust (all the cases 1 at a time)

    let result = check_node_crypto_keys_invariants(&snapshot);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&missing_node_id.to_string()));
    assert_eq!(
        err.to_string(),
        format!(
            "InvariantCheckError: There are {} or {} entries without a corresponding {} entry: [{}]",
            CRYPTO_RECORD_KEY_PREFIX, CRYPTO_TLS_CERT_KEY_PREFIX, NODE_RECORD_KEY_PREFIX, missing_node_id
        )
    );
}

mod ecdsa_signing_subnet_lists {
    use super::*;
    use ic_base_types::{subnet_id_into_protobuf, SubnetId};
    use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId};
    use ic_protobuf::registry::crypto::v1::EcdsaSigningSubnetList;
    use ic_protobuf::registry::subnet::v1::{EcdsaConfig, SubnetRecord};
    use ic_registry_transport::pb::v1::RegistryMutation;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use rand::Rng;

    #[test]
    fn should_succeed_for_valid_snapshot() {
        let setup = Setup::builder()
            .with_default_curve_and_key_id_and_subnet_record_ecdsa_config()
            .build();

        assert_matches!(check_node_crypto_keys_invariants(&setup.snapshot), Ok(()));
    }

    #[test]
    fn should_fail_subnet_existence_check_for_funky_key_id_lengths_and_characters_but_without_subnet_record(
    ) {
        const NUM_KEY_IDS: usize = 100;
        let rng = &mut ic_crypto_test_utils_reproducible_rng::reproducible_rng();
        for _ in 0..NUM_KEY_IDS {
            let len = rng.gen_range(1..100);
            let key_id: String = rng
                .sample_iter::<char, _>(rand::distributions::Standard)
                .take(len)
                .collect();
            let ecdsa_key_id = format!("{:?}:{}", EcdsaCurve::Secp256k1, key_id);
            let setup = Setup::builder()
                .with_custom_curve_and_key_id(ecdsa_key_id.clone())
                .without_subnet_record()
                .build();

            assert_matches!(
                check_node_crypto_keys_invariants(&setup.snapshot),
                Err(InvariantCheckError{msg: error_message, source: _})
                if error_message.contains(format!(
                    "A non-existent subnet {} was set as the holder of a key_id key_id_{}",
                    setup.subnet_id, ecdsa_key_id).as_str()
                )
            );
        }
    }

    #[test]
    fn should_succeed_if_same_key_configured_for_multiple_subnets() {
        let setup = Setup::builder()
            .with_default_curve_and_key_id_and_subnet_record_ecdsa_config()
            .with_same_key_on_additional_subnet(subnet_test_id(2))
            .build();

        assert_matches!(check_node_crypto_keys_invariants(&setup.snapshot), Ok(()));
    }

    #[test]
    fn should_fail_if_key_id_specifies_invalid_ecdsa_curve() {
        let key_id = "some_key1";
        let invalid_curves = vec!["bogus_curve", ""];
        for invalid_curve in invalid_curves {
            let ecdsa_key_id_string = format!("{}:{}", invalid_curve, key_id);
            let setup = Setup::builder()
                .with_custom_curve_and_key_id(ecdsa_key_id_string)
                .without_subnet_record()
                .build();

            assert_matches!(
                check_node_crypto_keys_invariants(&setup.snapshot),
                Err(InvariantCheckError{msg: error_message, source: _})
                if error_message.contains(format!("{} is not a recognized ECDSA curve", invalid_curve).as_str())
            );
        }
    }

    #[test]
    fn should_fail_if_key_id_does_not_contain_curve_and_id_separator() {
        let invalid_key_ids = vec!["bogus_curve_no_separator_some_key1", ""];
        for invalid_key_id in invalid_key_ids {
            let ecdsa_key_id_string = String::from(invalid_key_id);
            let setup = Setup::builder()
                .with_custom_curve_and_key_id(ecdsa_key_id_string.clone())
                .without_subnet_record()
                .build();

            assert_matches!(
                check_node_crypto_keys_invariants(&setup.snapshot),
                Err(InvariantCheckError{msg: error_message, source: _})
                if error_message.contains(
                    format!("ECDSA key id {} does not contain a ':'", ecdsa_key_id_string).as_str()
                )
            );
        }
    }

    #[test]
    fn should_fail_if_no_subnet_record_is_configured() {
        let setup = Setup::builder()
            .with_default_curve_and_key_id_and_subnet_record_ecdsa_config()
            .without_subnet_record()
            .build();

        assert_matches!(
            check_node_crypto_keys_invariants(&setup.snapshot),
            Err(InvariantCheckError{msg: error_message, source: _})
            if error_message.contains(format!(
                "A non-existent subnet {} was set as the holder of a key_id {}{}",
                setup.subnet_id,
                ic_registry_keys::ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX,
                setup.key_id.expect("a valid EcdsaKeyId should be set")
            ).as_str())
        );
    }

    #[test]
    fn should_fail_if_subnet_record_does_not_contain_an_ecdsa_config() {
        let setup = Setup::builder()
            .with_default_curve_and_key_id_and_subnet_record_ecdsa_config()
            .without_subnet_record_ecdsa_config()
            .build();

        assert_matches!(
            check_node_crypto_keys_invariants(&setup.snapshot),
            Err(InvariantCheckError{msg: error_message, source: _})
            if error_message.contains(format!(
                "The subnet {} does not have an ECDSA config",
                setup.subnet_id
            ).as_str())
        );
    }

    #[test]
    fn should_fail_if_expected_key_id_is_not_included_in_ecdsa_config_of_subnet_record() {
        let setup = Setup::builder()
            .with_default_curve_and_key_id_and_subnet_record_ecdsa_config()
            .with_subnet_record_ecdsa_config_key_ids(vec![EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "key2".to_string(),
            }])
            .build();

        assert_matches!(
            check_node_crypto_keys_invariants(&setup.snapshot),
            Err(InvariantCheckError{msg: error_message, source: _})
            if error_message.contains(format!(
                "The subnet {} does not have the key with {}{} in its ecdsa configurations",
                setup.subnet_id,
                ic_registry_keys::ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX,
                setup.key_id.expect("a valid EcdsaKeyId should be set")
            ).as_str())
        );
    }

    struct Setup {
        snapshot: RegistrySnapshot,
        key_id: Option<EcdsaKeyId>,
        subnet_id: SubnetId,
    }

    impl Setup {
        fn builder() -> SetupBuilder {
            SetupBuilder {
                custom_curve_and_key_id: None,
                default_curve_and_key_id: None,
                additional_subnet_id: None,
                with_subnet_record: true,
                with_subnet_record_ecdsa_config: true,
                subnet_record_ecdsa_config_key_ids: None,
            }
        }
    }

    struct SetupBuilder {
        custom_curve_and_key_id: Option<String>,
        default_curve_and_key_id: Option<EcdsaKeyId>,
        additional_subnet_id: Option<SubnetId>,
        with_subnet_record: bool,
        with_subnet_record_ecdsa_config: bool,
        subnet_record_ecdsa_config_key_ids: Option<Vec<EcdsaKeyId>>,
    }

    impl SetupBuilder {
        fn with_custom_curve_and_key_id(mut self, curve_and_key_id: String) -> Self {
            self.custom_curve_and_key_id = Some(curve_and_key_id);
            self
        }

        fn with_default_curve_and_key_id_and_subnet_record_ecdsa_config(mut self) -> Self {
            let default_ecdsa_key_id = EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "key1".to_string(),
            };
            self.default_curve_and_key_id = Some(default_ecdsa_key_id.clone());
            self.subnet_record_ecdsa_config_key_ids = Some(vec![default_ecdsa_key_id]);
            self
        }

        fn with_subnet_record_ecdsa_config_key_ids(mut self, key_ids: Vec<EcdsaKeyId>) -> Self {
            self.subnet_record_ecdsa_config_key_ids = Some(key_ids);
            self
        }

        fn with_same_key_on_additional_subnet(mut self, subnet_id: SubnetId) -> Self {
            self.additional_subnet_id = Some(subnet_id);
            self
        }

        fn without_subnet_record(mut self) -> Self {
            self.with_subnet_record = false;
            self
        }

        fn without_subnet_record_ecdsa_config(mut self) -> Self {
            self.with_subnet_record_ecdsa_config = false;
            self
        }

        fn build(self) -> Setup {
            let mut snapshot = RegistrySnapshot::new();
            let ecdsa_signing_subnet_list_key = format!(
                "{}{}",
                ic_registry_keys::ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX,
                self.default_curve_and_key_id.as_ref().map_or_else(
                    || self.custom_curve_and_key_id
                        .expect("either a valid EcdsaKeyId, or an invalid (curve, key_id) shall be specified"),
                    |key_id| key_id.to_string()
                )
            );
            let subnet_id = subnet_test_id(1);
            let mut subnets = vec![subnet_id_into_protobuf(subnet_id)];
            if let Some(another_subnet_id) = self.additional_subnet_id {
                subnets.push(subnet_id_into_protobuf(another_subnet_id));
            }
            let mut mutations: Vec<RegistryMutation> = vec![];
            let subnets_value = EcdsaSigningSubnetList { subnets };
            mutations.push(ic_registry_transport::insert(
                ecdsa_signing_subnet_list_key,
                encode_or_panic(&subnets_value),
            ));
            let node_id = node_test_id(1);
            if self.with_subnet_record {
                let ecdsa_config =
                    self.with_subnet_record_ecdsa_config
                        .then_some(EcdsaConfig::from(
                            ic_registry_subnet_features::EcdsaConfig {
                                key_ids: self
                                    .subnet_record_ecdsa_config_key_ids
                                    .expect("subnet_record_ecdsa_config_key_ids should be set"),
                                ..Default::default()
                            },
                        ));
                let subnet_record = SubnetRecord {
                    membership: vec![node_id.get().into_vec()],
                    ecdsa_config: ecdsa_config.clone(),
                    // TODO[NNS1-2969]: Use chain_key_config rather than ecdsa_config.
                    ..Default::default()
                };
                mutations.push(ic_registry_transport::insert(
                    make_subnet_record_key(subnet_id),
                    encode_or_panic(&subnet_record),
                ));
                if let Some(another_subnet_id) = self.additional_subnet_id {
                    let node_id = node_test_id(2);
                    let subnet_record = SubnetRecord {
                        membership: vec![node_id.get().into_vec()],
                        ecdsa_config,
                        // TODO[NNS1-2969]: Use chain_key_config rather than ecdsa_config.
                        ..Default::default()
                    };
                    mutations.push(ic_registry_transport::insert(
                        make_subnet_record_key(another_subnet_id),
                        encode_or_panic(&subnet_record),
                    ));
                }
            }
            for m in mutations {
                snapshot.insert(m.key, m.value);
            }

            Setup {
                snapshot,
                key_id: self.default_curve_and_key_id,
                subnet_id,
            }
        }
    }
}
