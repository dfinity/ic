use ic_crypto_temp_crypto::CryptoComponentRng;
use ic_crypto_temp_crypto::TempCryptoComponentGeneric;
use ic_crypto_test_utils::crypto_for;
use ic_crypto_test_utils_ni_dkg::{
    run_ni_dkg_and_create_single_transcript, NiDkgTestEnvironment, RandomNiDkgConfig,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::VetKdProtocol;
use ic_interfaces::crypto::{LoadTranscriptResult, NiDkgAlgorithm};
use ic_types::crypto::canister_threshold_sig::MasterPublicKey;
use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgConfig;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTranscript};
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::vetkd::VetKdArgs;
use ic_types::crypto::vetkd::VetKdDerivationDomain;
use ic_types::crypto::vetkd::VetKdEncryptedKey;
use ic_types::crypto::vetkd::VetKdEncryptedKeyShare;
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeId, NumberOfNodes};
use ic_types_test_utils::ids::canister_test_id;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

#[test]
fn should_consistently_derive_the_same_vetkey_given_sufficient_shares() {
    let rng = &mut reproducible_rng();
    let subnet_size = rng.gen_range(1..7);
    let (config, dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size, rng);

    let transcript = run_ni_dkg_and_load_transcript_for_receivers(&config, &crypto_components);

    let derivation_domain = VetKdDerivationDomain {
        caller: canister_test_id(234).get(),
        domain: b"domain-123".to_vec(),
    };
    let derived_public_key = ic_crypto_utils_canister_threshold_sig::derive_vetkd_public_key(
        &MasterPublicKey {
            algorithm_id: AlgorithmId::VetKD,
            public_key: ThresholdSigPublicKey::try_from(&transcript)
                .expect("invalid transcript")
                .into_bytes()
                .to_vec(),
        },
        &derivation_domain,
    )
    .expect("failed to compute derived public key");
    let transport_secret_key =
        ic_vetkd_utils::TransportSecretKey::from_seed(rng.gen::<[u8; 32]>().to_vec())
            .expect("failed to create transport secret key");
    let vetkd_args = VetKdArgs {
        ni_dkg_id: dkg_id,
        derivation_domain,
        derivation_id: b"some-derivation-id".to_vec(),
        encryption_public_key: transport_secret_key.public_key(),
    };

    let mut expected_decrypted_key: Option<Vec<u8>> = None;
    for _ in 1..=3 {
        let encrypted_key = create_key_shares_and_verify_and_combine(
            KeyShareCreatorsAndCombiner {
                creators: n_random_nodes_in(
                    config.receivers().get(),
                    config.threshold().get(),
                    rng,
                ),
                combiner: random_node_in(config.receivers().get(), rng),
            },
            &vetkd_args,
            &crypto_components,
        );

        let random_verifier = random_node_in(config.receivers().get(), rng);
        assert_eq!(
            crypto_for(random_verifier, &crypto_components)
                .verify_encrypted_key(&encrypted_key, &vetkd_args),
            Ok(())
        );

        let decrypted_key = transport_secret_key
            .decrypt(
                &encrypted_key.encrypted_key,
                &derived_public_key,
                &vetkd_args.derivation_id,
            )
            .expect("failed to decrypt vetKey");

        if let Some(expected_decrypted_key) = &expected_decrypted_key {
            assert_eq!(&decrypted_key, expected_decrypted_key);
        } else {
            expected_decrypted_key = Some(decrypted_key);
        }
    }
}

fn setup_with_random_ni_dkg_config<R: Rng + CryptoRng>(
    subnet_size: usize,
    rng: &mut R,
) -> (
    NiDkgConfig,
    NiDkgId,
    BTreeMap<NodeId, TempCryptoComponentGeneric<ChaCha20Rng>>,
) {
    let config = RandomNiDkgConfig::builder()
        .subnet_size(subnet_size)
        .build(rng)
        .into_config();
    let dkg_id = config.dkg_id().clone();
    let crypto_components =
        NiDkgTestEnvironment::new_for_config_with_remote_vault(&config, rng).crypto_components;
    (config, dkg_id, crypto_components)
}

fn create_key_shares_and_verify_and_combine<C: CryptoComponentRng>(
    creators_and_combiner: KeyShareCreatorsAndCombiner,
    vetkd_args: &VetKdArgs,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
) -> VetKdEncryptedKey {
    let key_shares = create_and_verify_key_shares_for_each(
        &creators_and_combiner.creators,
        vetkd_args,
        crypto_components,
    );
    crypto_for(creators_and_combiner.combiner, crypto_components)
        .combine_encrypted_key_shares(&key_shares, vetkd_args)
        .expect("failed to combine signature shares")
}

fn create_and_verify_key_shares_for_each<C: CryptoComponentRng>(
    key_share_creators: &[NodeId],
    vetkd_args: &VetKdArgs,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
) -> BTreeMap<NodeId, VetKdEncryptedKeyShare> {
    key_share_creators
        .iter()
        .map(|creator| {
            let crypto = crypto_for(*creator, crypto_components);
            let key_share = crypto
                .create_encrypted_key_share(vetkd_args.clone())
                .unwrap_or_else(|e| {
                    panic!(
                        "vetKD encrypted key share creation by node {:?} failed: {}",
                        creator, e
                    )
                });
            assert_eq!(
                crypto.verify_encrypted_key_share(*creator, &key_share, vetkd_args),
                Ok(())
            );
            (*creator, key_share)
        })
        .collect()
}

#[derive(Clone, Debug)]
struct KeyShareCreatorsAndCombiner {
    creators: Vec<NodeId>,
    combiner: NodeId,
}

/////////////////////////////////////////////////////////////////////////////////
// The following helper functions where copied from threshold_sigs_with_ni_dkg.rs
/////////////////////////////////////////////////////////////////////////////////

fn run_ni_dkg_and_load_transcript_for_receivers<C: CryptoComponentRng>(
    config: &NiDkgConfig,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
) -> NiDkgTranscript {
    let transcript = run_ni_dkg_and_create_single_transcript(config, crypto_components);
    load_transcript_for_receivers_expecting_status(
        config,
        &transcript,
        crypto_components,
        Some(LoadTranscriptResult::SigningKeyAvailable),
    );
    transcript
}

fn load_transcript_for_receivers_expecting_status<C: CryptoComponentRng>(
    config: &NiDkgConfig,
    transcript: &NiDkgTranscript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
    expected_status: Option<LoadTranscriptResult>,
) {
    for node_id in config.receivers().get() {
        let result = crypto_for(*node_id, crypto_components).load_transcript(transcript);

        if result.is_err() {
            panic!(
                "failed to load transcript {} for node {}: {}",
                transcript,
                *node_id,
                result.unwrap_err()
            );
        }

        if let Some(expected_status) = expected_status {
            let result = result.unwrap();
            assert_eq!(result, expected_status);
        }
    }
}

fn random_node_in<R: Rng + CryptoRng>(nodes: &BTreeSet<NodeId>, rng: &mut R) -> NodeId {
    *nodes.iter().choose(rng).expect("nodes empty")
}

fn n_random_nodes_in<R: Rng + CryptoRng>(
    nodes: &BTreeSet<NodeId>,
    n: NumberOfNodes,
    rng: &mut R,
) -> Vec<NodeId> {
    let n_usize = usize::try_from(n.get()).expect("conversion to usize failed");
    let chosen = nodes.iter().copied().choose_multiple(rng, n_usize);
    assert_eq!(chosen.len(), n_usize);
    chosen
}
