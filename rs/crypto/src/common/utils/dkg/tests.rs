use super::*;
use ic_crypto_internal_csp::types::CspPop;
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::EphemeralPopBytes;
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::secp256k1::EphemeralPublicKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::{
    CspEncryptionPublicKey, InternalCspEncryptionPublicKey,
};
use ic_test_utilities::types::ids::{node_test_id, subnet_test_id, SUBNET_1};
use ic_types::crypto::dkg::{EncryptionPublicKey, EncryptionPublicKeyPop};

#[test]
#[should_panic(expected = "subnet must not be empty")]
fn should_panic_on_empty_nodes_in_subnet() {
    let nodes = [];
    let nodes_set: BTreeSet<NodeId> = nodes.iter().cloned().collect();
    let subnet_id = subnet_test_id(1);

    InitialDkgConfig::new(&nodes_set, subnet_id);
}

#[test]
fn should_correctly_create_initial_dkg_config_for_single_node() {
    let nodes = [node_id(5)];
    let nodes_set: BTreeSet<NodeId> = nodes.iter().cloned().collect();
    let subnet_id = subnet_test_id(1);

    let initial_dkg_config = InitialDkgConfig::new(&nodes_set, subnet_id);

    assert_eq!(
        initial_dkg_config.dkg_config,
        dkg::Config {
            dkg_id: IDkgId {
                instance_id: Height::from(0),
                subnet_id
            },
            dealers: vec![node_id(1)],
            receivers: nodes.to_vec(),
            threshold: 1,
            resharing_transcript: None
        }
    );
}

#[test]
fn should_correctly_create_initial_dkg_config() {
    let nodes = [node_id(2), node_id(3), node_id(5), node_id(6), node_id(7)];
    let nodes_set: BTreeSet<NodeId> = nodes.iter().cloned().collect();
    let subnet_id = subnet_test_id(1);

    let initial_dkg_config = InitialDkgConfig::new(&nodes_set, subnet_id);

    assert_eq!(
        initial_dkg_config.dkg_config,
        dkg::Config {
            dkg_id: IDkgId {
                instance_id: Height::from(0),
                subnet_id
            },
            dealers: vec![node_id(1), node_id(4)],
            receivers: nodes.to_vec(),
            threshold: 2,
            resharing_transcript: None
        }
    );
}

#[test]
fn should_create_initial_dkg_config_with_disjoint_dealers_and_receivers() {
    let nodes = [node_id(2), node_id(3), node_id(5), node_id(6), node_id(7)];
    let nodes_set: BTreeSet<NodeId> = nodes.iter().cloned().collect();
    let subnet_id = subnet_test_id(1);

    let dkg_config = InitialDkgConfig::new(&nodes_set, subnet_id).dkg_config;

    let dealer_set: BTreeSet<NodeId> = dkg_config.dealers.iter().cloned().collect();
    let receiver_set: BTreeSet<NodeId> = dkg_config.receivers.iter().cloned().collect();
    assert!(
        dealer_set.is_disjoint(&receiver_set),
        "dealers and receivers must be disjoint"
    );
}

#[test]
fn should_correctly_combine_dealer_and_receiver_keys() {
    let dealer_keys = keys(vec![
        (node_id(1), enc_pk_with_pop(1)),
        (node_id(2), enc_pk_with_pop(2)),
    ]);
    let receiver_keys = keys(vec![
        (node_id(3), enc_pk_with_pop(3)),
        (node_id(4), enc_pk_with_pop(4)),
    ]);

    let dealer_and_receiver_keys = dealer_and_receiver_keys(&dealer_keys, &receiver_keys);

    assert_eq!(
        dealer_and_receiver_keys,
        keys(vec![
            (node_id(1), enc_pk_with_pop(1)),
            (node_id(2), enc_pk_with_pop(2)),
            (node_id(3), enc_pk_with_pop(3)),
            (node_id(4), enc_pk_with_pop(4)),
        ])
    );
}

#[test]
#[should_panic(expected = "the config's receivers must match the keys' receivers")]
fn should_panic_if_receiver_keys_dont_match_config_receivers() {
    let nodes = [node_id(2), node_id(3), node_id(5), node_id(6), node_id(7)];
    let nodes_set: BTreeSet<NodeId> = nodes.iter().cloned().collect();
    let subnet_id = subnet_test_id(1);
    let initial_dkg_config = InitialDkgConfig::new(&nodes_set, subnet_id);
    let receiver_keys = BTreeMap::new();

    initial_dkg_transcript(initial_dkg_config, &receiver_keys);
}

#[test]
fn should_correctly_calculate_threshold() {
    assert_eq!(get_threshold_for_committee_of_size(0), 0);
    assert_eq!(get_threshold_for_committee_of_size(1), 1);
    assert_eq!(get_threshold_for_committee_of_size(2), 1);
    assert_eq!(get_threshold_for_committee_of_size(3), 1);
    assert_eq!(get_threshold_for_committee_of_size(4), 2);
    assert_eq!(get_threshold_for_committee_of_size(6), 2);
    assert_eq!(get_threshold_for_committee_of_size(28), 10);
}

fn keys(
    content: Vec<(NodeId, EncryptionPublicKeyWithPop)>,
) -> BTreeMap<NodeId, EncryptionPublicKeyWithPop> {
    let mut keys = BTreeMap::new();
    for (node_id, key) in content {
        keys.insert(node_id, key);
    }
    keys
}

fn node_id(node_id: u64) -> NodeId {
    node_test_id(node_id)
}

fn enc_pk_with_pop(content: u8) -> EncryptionPublicKeyWithPop {
    EncryptionPublicKeyWithPop {
        key: EncryptionPublicKey::from(&csp_enc_pk(content)),
        proof_of_possession: EncryptionPublicKeyPop::from(&csp_pop(content)),
    }
}

fn csp_enc_pk(content: u8) -> CspEncryptionPublicKey {
    CspEncryptionPublicKey {
        internal: InternalCspEncryptionPublicKey::Secp256k1(EphemeralPublicKeyBytes(
            [content; EphemeralPublicKeyBytes::SIZE],
        )),
    }
}

fn csp_pop(content: u8) -> CspPop {
    CspPop::Secp256k1(EphemeralPopBytes([content; EphemeralPopBytes::SIZE]))
}

mod transcript_to_protobuf_conversion {
    use super::*;
    use ic_protobuf::registry::subnet::v1::DkgId as protobuf_DkgId;

    const DKG_ID: IDkgId = IDkgId {
        instance_id: Height::new(1),
        subnet_id: SUBNET_1,
    };

    #[test]
    fn should_correctly_convert_transcript_to_protobuf() {
        let transcript_bytes = vec![1, 2, 3, 4];
        let transcript = dkg::Transcript {
            dkg_id: DKG_ID,
            committee: vec![Some(node_id(42)), Some(node_id(17))],
            transcript_bytes: dkg::TranscriptBytes(transcript_bytes.clone()),
        };

        let protobuf = initial_dkg_transcript_record_from_transcript(transcript);

        assert_eq!(
            protobuf,
            InitialDkgTranscriptRecord {
                id: Some(protobuf_DkgId {
                    subnet_id: DKG_ID.subnet_id.get().into_vec(),
                    instance_id: DKG_ID.instance_id.get(),
                }),
                committee: vec![node_id(42).get().into_vec(), node_id(17).get().into_vec()],
                transcript_bytes,
            }
        );
    }

    #[test]
    #[should_panic(expected = "invalid initial DKG transcript")]
    fn should_panic_on_invalid_initial_dkg_transcript() {
        let transcript = dkg::Transcript {
            dkg_id: DKG_ID,
            committee: vec![Some(node_id(42)), None],
            transcript_bytes: dkg::TranscriptBytes(vec![1, 2, 3, 4]),
        };

        let _panic = initial_dkg_transcript_record_from_transcript(transcript);
    }
}
