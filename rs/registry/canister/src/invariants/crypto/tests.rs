use super::*;
use assert_matches::assert_matches;
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::generate_node_keys_once;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_test_utils_ni_dkg::{InitialNiDkgConfig, initial_dkg_transcript_and_master_key};
use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
use ic_crypto_utils_ni_dkg::extract_threshold_sig_public_key;
use ic_nns_test_utils::registry::new_current_node_crypto_keys_mutations;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::subnet::v1::{
    CatchUpPackageContents, InitialNiDkgTranscriptRecord, SubnetListRecord,
};
use ic_registry_keys::make_catch_up_package_contents_key;
use ic_registry_keys::{make_node_record_key, make_subnet_list_record_key};
use ic_registry_transport::insert;
use ic_types::RegistryVersion;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTargetId, NiDkgTranscript};
use ic_types_test_utils::ids::{SUBNET_1, SUBNET_2};
use prost::Message;
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
        NodeRecord::default().encode_to_vec(),
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
        subnet_list_record.encode_to_vec(),
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
    let pubkey_value = bad_pubkey_bytes.encode_to_vec();
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
    let cup_mutation = insert(cup_contents_key, bad_cup_contents_bytes.encode_to_vec());
    snapshot.insert(cup_mutation.key, cup_mutation.value);

    assert!(check_high_threshold_public_key_matches_the_one_in_cup(&snapshot).is_err());
}

#[test]
fn high_threshold_public_key_invariant_unable_to_parse_initial_ni_dkg_transcript_high_threshold_in_cup()
 {
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
    let cup_mutation = insert(cup_contents_key, setup.cup_contents.encode_to_vec());
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
        let cup_mutation = insert(cup_contents_key, cup_contents.encode_to_vec());
        snapshot.insert(cup_mutation.key, cup_mutation.value);
    }
    let subnet_list_record = SubnetListRecord {
        subnets: vec![receiver_subnet.get().into_vec()],
    };
    let subnet_list_record_key = make_subnet_list_record_key();
    let subnet_mutation = insert(
        subnet_list_record_key.into_bytes(),
        subnet_list_record.encode_to_vec(),
    );
    snapshot.insert(subnet_mutation.key, subnet_mutation.value);
    if let Some(threshold_sig_pk) = threshold_sig_pk {
        let pubkey_key = make_crypto_threshold_signing_pubkey_key(receiver_subnet);
        let pubkey_proto = PublicKey::from(threshold_sig_pk);
        let pubkey_value = pubkey_proto.encode_to_vec();
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
            "InvariantCheckError: There are {CRYPTO_RECORD_KEY_PREFIX} or {CRYPTO_TLS_CERT_KEY_PREFIX} entries without a corresponding {NODE_RECORD_KEY_PREFIX} entry: [{missing_node_id}]"
        )
    );
}

mod chain_key_enabled_subnet_lists {
    use super::*;
    use crate::common::test_helpers::invariant_compliant_registry;
    use ic_base_types::{SubnetId, subnet_id_into_protobuf};
    use ic_management_canister_types_private::{EcdsaCurve, EcdsaKeyId, MasterPublicKeyId};
    use ic_protobuf::registry::crypto::v1::ChainKeyEnabledSubnetList;
    use ic_protobuf::registry::subnet::v1::{
        ChainKeyConfig as ChainKeyConfigPb, KeyConfig as KeyConfigPb,
        SubnetRecord as SubnetRecordPb,
    };
    use ic_protobuf::types::v1::{
        self as pb, MasterPublicKeyId as MasterPublicKeyIdPb, master_public_key_id,
    };
    use ic_registry_keys::CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX;
    use ic_registry_subnet_features::KeyConfig;
    use ic_registry_transport::pb::v1::RegistryMutation;
    use ic_registry_transport::upsert;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::PrincipalId;
    use prost::Message;
    use rand::Rng;

    fn invariant_compliant_chain_key_config() -> ChainKeyConfigPb {
        ChainKeyConfigPb {
            key_configs: vec![
                KeyConfigPb {
                    key_id: Some(MasterPublicKeyIdPb {
                        key_id: Some(master_public_key_id::KeyId::Ecdsa(pb::EcdsaKeyId {
                            curve: 1,
                            name: "ecdsa_key".to_string(),
                        })),
                    }),
                    pre_signatures_to_create_in_advance: Some(456),
                    max_queue_size: Some(100),
                },
                KeyConfigPb {
                    key_id: Some(MasterPublicKeyIdPb {
                        key_id: Some(master_public_key_id::KeyId::Schnorr(pb::SchnorrKeyId {
                            algorithm: 1,
                            name: "schnorr_key".to_string(),
                        })),
                    }),
                    pre_signatures_to_create_in_advance: Some(456),
                    max_queue_size: Some(100),
                },
                KeyConfigPb {
                    key_id: Some(MasterPublicKeyIdPb {
                        key_id: Some(master_public_key_id::KeyId::Vetkd(pb::VetKdKeyId {
                            curve: 1,
                            name: "vetkd_key".to_string(),
                        })),
                    }),
                    pre_signatures_to_create_in_advance: None,
                    max_queue_size: Some(100),
                },
            ],
            signature_request_timeout_ns: Some(10_000),
            idkg_key_rotation_period_ms: Some(20_000),
            max_parallel_pre_signature_transcripts_in_creation: Some(30_000),
        }
    }

    fn check_chain_key_config_invariant(config: ChainKeyConfigPb) {
        let registry = invariant_compliant_registry(0);

        let list = registry.get_subnet_list_record();
        let nns_id = SubnetId::from(PrincipalId::try_from(list.subnets.first().unwrap()).unwrap());
        let mut subnet = registry.get_subnet_or_panic(nns_id);
        subnet.chain_key_config = Some(config);

        let new_subnet = upsert(
            make_subnet_record_key(nns_id).into_bytes(),
            subnet.encode_to_vec(),
        );
        registry.check_global_state_invariants(&[new_subnet]);
    }

    #[test]
    fn should_succeed_with_invariant_compliant_config() {
        check_chain_key_config_invariant(invariant_compliant_chain_key_config());
    }

    #[test]
    #[should_panic(
        expected = "Missing required struct field: KeyConfig::pre_signatures_to_create_in_advance"
    )]
    fn should_fail_if_missing_pre_signatures_for_key_that_requires_pre_signatures() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs[1].pre_signatures_to_create_in_advance = None;
        check_chain_key_config_invariant(config);
    }

    #[test]
    #[should_panic(
        expected = "pre_signatures_to_create_in_advance for key ecdsa:Secp256k1:ecdsa_key of subnet ya35z-hhham-aaaaa-aaaap-yai must be non-zero"
    )]
    fn should_fail_if_pre_signatures_is_zero_for_key_that_requires_pre_signatures() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs[0].pre_signatures_to_create_in_advance = Some(0);
        check_chain_key_config_invariant(config);
    }

    #[test]
    fn should_succeed_if_pre_signatures_is_missing_for_key_that_does_not_require_pre_signatures() {
        let mut config = invariant_compliant_chain_key_config();
        let key_config = &mut config.key_configs[2];
        assert!(matches!(
            key_config.key_id.as_ref().unwrap().key_id,
            Some(master_public_key_id::KeyId::Vetkd(_))
        ),);
        key_config.pre_signatures_to_create_in_advance = None;
        check_chain_key_config_invariant(config);
    }

    #[test]
    fn should_succeed_if_pre_signatures_is_zero_for_key_that_does_not_require_pre_signatures() {
        let mut config = invariant_compliant_chain_key_config();
        let key_config = &mut config.key_configs[2];
        assert!(matches!(
            key_config.key_id.as_ref().unwrap().key_id,
            Some(master_public_key_id::KeyId::Vetkd(_))
        ),);
        key_config.pre_signatures_to_create_in_advance = Some(0);
        check_chain_key_config_invariant(config);
    }

    #[test]
    #[should_panic(expected = "Missing required struct field: KeyConfig::max_queue_size")]
    fn should_fail_if_missing_queue_size() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs[1].max_queue_size = None;
        check_chain_key_config_invariant(config);
    }

    #[test]
    #[should_panic(expected = "Missing required struct field: KeyConfig::key_id")]
    fn should_fail_if_missing_key_id() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs[1].key_id = None;
        check_chain_key_config_invariant(config);
    }

    #[test]
    #[should_panic(expected = "Unable to convert 2 to an EcdsaCurve")]
    fn should_fail_if_unkown_ecdsa_curve() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs[1].key_id = Some(MasterPublicKeyIdPb {
            key_id: Some(master_public_key_id::KeyId::Ecdsa(pb::EcdsaKeyId {
                curve: 2,
                name: "ecdsa_key".to_string(),
            })),
        });
        check_chain_key_config_invariant(config);
    }

    #[test]
    #[should_panic(expected = "Unable to convert 3 to a SchnorrAlgorithm")]
    fn should_fail_if_unkown_schnorr_algorithm() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs[1].key_id = Some(MasterPublicKeyIdPb {
            key_id: Some(master_public_key_id::KeyId::Schnorr(pb::SchnorrKeyId {
                algorithm: 3,
                name: "schnorr_key".to_string(),
            })),
        });
        check_chain_key_config_invariant(config);
    }

    #[test]
    #[should_panic(expected = "Unable to convert 2 to a VetKdCurve")]
    fn should_fail_if_unkown_vetkd_curve() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs[1].key_id = Some(MasterPublicKeyIdPb {
            key_id: Some(master_public_key_id::KeyId::Vetkd(pb::VetKdKeyId {
                curve: 2,
                name: "vetkd_key".to_string(),
            })),
        });
        check_chain_key_config_invariant(config);
    }

    #[test]
    #[should_panic(expected = "Unable to convert Unspecified to an EcdsaCurve")]
    fn should_fail_if_unspecified_ecdsa_curve() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs[1].key_id = Some(MasterPublicKeyIdPb {
            key_id: Some(master_public_key_id::KeyId::Ecdsa(pb::EcdsaKeyId {
                curve: 0,
                name: "ecdsa_key".to_string(),
            })),
        });
        check_chain_key_config_invariant(config);
    }

    #[test]
    #[should_panic(expected = "Unable to convert Unspecified to a SchnorrAlgorithm")]
    fn should_fail_if_unspecified_schnorr_algorithm() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs[1].key_id = Some(MasterPublicKeyIdPb {
            key_id: Some(master_public_key_id::KeyId::Schnorr(pb::SchnorrKeyId {
                algorithm: 0,
                name: "schnorr_key".to_string(),
            })),
        });
        check_chain_key_config_invariant(config);
    }

    #[test]
    #[should_panic(expected = "Unable to convert Unspecified to a VetKdCurve")]
    fn should_fail_if_unspecified_vetkd_curve() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs[1].key_id = Some(MasterPublicKeyIdPb {
            key_id: Some(master_public_key_id::KeyId::Vetkd(pb::VetKdKeyId {
                curve: 0,
                name: "vetkd_key".to_string(),
            })),
        });
        check_chain_key_config_invariant(config);
    }

    #[test]
    #[should_panic(
        expected = "ChainKeyConfig of subnet ya35z-hhham-aaaaa-aaaap-yai contains multiple entries for key ID schnorr:Bip340Secp256k1:schnorr_key."
    )]
    fn should_fail_if_duplicate_key_ids() {
        let mut config = invariant_compliant_chain_key_config();
        config.key_configs.push(config.key_configs[1].clone());
        check_chain_key_config_invariant(config);
    }

    #[test]
    fn should_succeed_for_valid_snapshot() {
        let setup = Setup::builder()
            .with_default_curve_and_key_id_and_subnet_record_ecdsa_config()
            .build();

        assert_matches!(check_node_crypto_keys_invariants(&setup.snapshot), Ok(()));
    }

    #[test]
    fn should_fail_subnet_existence_check_for_funky_key_id_lengths_and_characters_but_without_subnet_record()
     {
        const NUM_KEY_IDS: usize = 100;
        let rng = &mut ic_crypto_test_utils_reproducible_rng::reproducible_rng();
        for _ in 0..NUM_KEY_IDS {
            let len = rng.gen_range(1..100);
            let key_id: String = rng
                .sample_iter::<char, _>(rand::distributions::Standard)
                .take(len)
                .collect();
            let ecdsa_key_id = format!("ecdsa:{:?}:{:?}", EcdsaCurve::Secp256k1, key_id);

            let setup = Setup::builder()
                .with_custom_curve_and_key_id(ecdsa_key_id.clone())
                .without_subnet_record()
                .build();

            assert_matches!(
                check_node_crypto_keys_invariants(&setup.snapshot),
                Err(InvariantCheckError{msg: error_message, source: _})
                if error_message.contains(format!(
                    "A non-existent subnet {} was set as the holder of a key_id {}{}",
                    setup.subnet_id, CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX, ecdsa_key_id
                ).as_str())
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
            let ecdsa_key_id_string = format!("{invalid_curve}:{key_id}");
            let setup = Setup::builder()
                .with_custom_curve_and_key_id(ecdsa_key_id_string.clone())
                .without_subnet_record()
                .build();

            assert_matches!(
                check_node_crypto_keys_invariants(&setup.snapshot),
                Err(err) if err.to_string().contains(
                    format!(
                        "Scheme {invalid_curve} in master public key id {ecdsa_key_id_string} is not supported",
                    ).as_str())
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
                Err(err) if err.to_string().contains(
                    format!("Master public key id {ecdsa_key_id_string} does not contain a ':'").as_str()
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
                ic_registry_keys::CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX,
                setup.key_id.expect("a valid MasterPublicKey should be set")
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
                "The subnet {} does not have a ChainKeyConfig",
                setup.subnet_id
            ).as_str())
        );
    }

    #[test]
    fn should_fail_if_expected_key_id_is_not_included_in_ecdsa_config_of_subnet_record() {
        let setup = Setup::builder()
            .with_default_curve_and_key_id_and_subnet_record_ecdsa_config()
            .with_subnet_record_ecdsa_config_key_ids(vec![MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "key2".to_string(),
            })])
            .build();

        assert_matches!(
            check_node_crypto_keys_invariants(&setup.snapshot),
            Err(InvariantCheckError{msg: error_message, source: _})
            if error_message.contains(format!(
                "The subnet {} does not have the key with {}{} in its chain key configurations",
                setup.subnet_id,
                ic_registry_keys::CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX,
                setup.key_id.expect("a valid MasterPublicKeyId should be set")
            ).as_str())
        );
    }

    struct Setup {
        snapshot: RegistrySnapshot,
        key_id: Option<MasterPublicKeyId>,
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
        default_curve_and_key_id: Option<MasterPublicKeyId>,
        additional_subnet_id: Option<SubnetId>,
        with_subnet_record: bool,
        with_subnet_record_ecdsa_config: bool,
        subnet_record_ecdsa_config_key_ids: Option<Vec<MasterPublicKeyId>>,
    }

    impl SetupBuilder {
        fn with_custom_curve_and_key_id(mut self, curve_and_key_id: String) -> Self {
            self.custom_curve_and_key_id = Some(curve_and_key_id);
            self
        }

        fn with_default_curve_and_key_id_and_subnet_record_ecdsa_config(mut self) -> Self {
            let default_key_id = EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "key1".to_string(),
            };
            let default_key_id = MasterPublicKeyId::Ecdsa(default_key_id);
            self.default_curve_and_key_id = Some(default_key_id.clone());
            self.subnet_record_ecdsa_config_key_ids = Some(vec![default_key_id]);
            self
        }

        fn with_subnet_record_ecdsa_config_key_ids(
            mut self,
            key_ids: Vec<MasterPublicKeyId>,
        ) -> Self {
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
            let key_id = match (&self.default_curve_and_key_id, self.custom_curve_and_key_id) {
                (Some(default_curve_and_key_id), _) => default_curve_and_key_id.to_string(),
                (None, Some(custom_curve_and_key_id)) => custom_curve_and_key_id,
                (None, None) => {
                    panic!(
                        "Either default_curve_and_key_id or custom_curve_and_key_id must be set."
                    );
                }
            };
            let chain_key_enabled_subnet_list_key =
                format!("{CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX}{key_id}");

            let subnet_id = subnet_test_id(1);
            let mut subnets = vec![subnet_id_into_protobuf(subnet_id)];
            if let Some(another_subnet_id) = self.additional_subnet_id {
                subnets.push(subnet_id_into_protobuf(another_subnet_id));
            }
            let mut mutations: Vec<RegistryMutation> = vec![];
            let subnets_value = ChainKeyEnabledSubnetList { subnets };
            mutations.push(ic_registry_transport::insert(
                chain_key_enabled_subnet_list_key,
                subnets_value.encode_to_vec(),
            ));
            let node_id = node_test_id(1);
            if self.with_subnet_record {
                let chain_key_config = if self.with_subnet_record_ecdsa_config {
                    let key_configs = self
                        .subnet_record_ecdsa_config_key_ids
                        .expect("subnet_record_ecdsa_config_key_ids must be set")
                        .iter()
                        .map(|key_id| KeyConfig {
                            key_id: key_id.clone(),
                            pre_signatures_to_create_in_advance: Default::default(),
                            max_queue_size: Default::default(),
                        })
                        .collect();
                    let chain_key_config = ChainKeyConfig {
                        key_configs,
                        ..Default::default()
                    };
                    Some(ChainKeyConfigPb::from(chain_key_config))
                } else {
                    None
                };
                let subnet_record = SubnetRecordPb {
                    membership: vec![node_id.get().into_vec()],
                    chain_key_config: chain_key_config.clone(),
                    ..Default::default()
                };
                mutations.push(ic_registry_transport::insert(
                    make_subnet_record_key(subnet_id),
                    subnet_record.encode_to_vec(),
                ));
                if let Some(another_subnet_id) = self.additional_subnet_id {
                    let node_id = node_test_id(2);
                    let subnet_record = SubnetRecordPb {
                        membership: vec![node_id.get().into_vec()],
                        chain_key_config,
                        ..Default::default()
                    };
                    mutations.push(ic_registry_transport::insert(
                        make_subnet_record_key(another_subnet_id),
                        subnet_record.encode_to_vec(),
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
