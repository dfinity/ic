use ic_crypto_temp_crypto::CryptoComponentRng;
use ic_crypto_temp_crypto::TempCryptoComponentGeneric;
use ic_crypto_test_utils::crypto_for;
use ic_crypto_test_utils_ni_dkg::{
    NiDkgTestEnvironment, RandomNiDkgConfig, run_ni_dkg_and_create_single_transcript,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_test_utils_vetkd::VetKdArgsOwned;
use ic_interfaces::crypto::VetKdProtocol;
use ic_interfaces::crypto::{LoadTranscriptResult, NiDkgAlgorithm};
use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgConfig;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTranscript};
use ic_types::crypto::vetkd::VetKdEncryptedKey;
use ic_types::crypto::vetkd::VetKdEncryptedKeyShare;
use ic_types::crypto::vetkd::VetKdEncryptedKeyShareContent;
use ic_types::crypto::vetkd::VetKdKeyShareCombinationError;
use ic_types::crypto::vetkd::VetKdKeyShareCreationError;
use ic_types::crypto::vetkd::VetKdKeyShareVerificationError;
use ic_types::crypto::vetkd::VetKdKeyVerificationError;
use ic_types::{CanisterId, NodeId};
use ic_types_test_utils::ids::canister_test_id;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use slog::Level;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

struct VetKDTestServer {
    env: NiDkgTestEnvironment,
    config: NiDkgConfig,
    dkg_id: NiDkgId,
    transcript: NiDkgTranscript,
}

impl VetKDTestServer {
    fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let subnet_size = 7;

        let config = RandomNiDkgConfig::builder()
            .subnet_size(subnet_size)
            .build(rng)
            .into_config();
        let dkg_id = config.dkg_id().clone();
        let env = NiDkgTestEnvironment::new_for_config_with_inmem_logger(&config, rng);

        let transcript = run_ni_dkg_and_create_single_transcript(&config, &env.crypto_components);
        load_transcript_for_receivers_expecting_status(
            &config,
            &transcript,
            &env.crypto_components,
            Some(LoadTranscriptResult::SigningKeyAvailable),
        );

        Self {
            env,
            config,
            dkg_id,
            transcript,
        }
    }

    fn derive_key(&self, caller: &CanisterId, context: &[u8]) -> ic_vetkeys::DerivedPublicKey {
        let transcript_key = ThresholdSigPublicKey::try_from(&self.transcript)
            .expect("invalid transcript")
            .into_bytes();

        let transcript_key = ic_vetkeys::MasterPublicKey::deserialize(&transcript_key)
            .expect("failed to deserialize transcript public key");

        transcript_key
            .derive_canister_key(caller.get().as_slice())
            .derive_sub_key(context)
    }

    fn random_node<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (NodeId, &TempCryptoComponentGeneric<ChaCha20Rng>) {
        let node_id = random_node_in(self.config.receivers().get(), rng);
        (node_id, crypto_for(node_id, &self.env.crypto_components))
    }

    fn create_key_shares<R: Rng + CryptoRng>(
        &self,
        vetkd_args: &VetKdArgsOwned,
        _rng: &mut R,
    ) -> Result<BTreeMap<NodeId, VetKdEncryptedKeyShare>, VetKdKeyShareCreationError> {
        let mut key_shares = BTreeMap::new();

        for creator in self.config.receivers().get() {
            let crypto = crypto_for(*creator, &self.env.crypto_components);
            let key_share = crypto.create_encrypted_key_share(vetkd_args.as_ref())?;
            key_shares.insert(*creator, key_share);
        }

        Ok(key_shares)
    }

    fn verify_key_shares<R: Rng + CryptoRng>(
        &self,
        shares: &BTreeMap<NodeId, VetKdEncryptedKeyShare>,
        vetkd_args: &VetKdArgsOwned,
        rng: &mut R,
    ) -> Result<(), VetKdKeyShareVerificationError> {
        let (_verifier_id, verifier) = self.random_node(rng);

        for (node_id, share) in shares {
            verifier.verify_encrypted_key_share(*node_id, share, &vetkd_args.as_ref())?
        }

        Ok(())
    }

    fn combine_key_shares<R: Rng + CryptoRng>(
        &self,
        shares: &BTreeMap<NodeId, VetKdEncryptedKeyShare>,
        vetkd_args: &VetKdArgsOwned,
        rng: &mut R,
    ) -> Result<(NodeId, VetKdEncryptedKey), VetKdKeyShareCombinationError> {
        let (combiner_id, combiner) = self.random_node(rng);
        combiner
            .combine_encrypted_key_shares(shares, &vetkd_args.as_ref())
            .map(|ek| (combiner_id, ek))
    }

    fn verify_encrypted_key<R: Rng + CryptoRng>(
        &self,
        ek: &VetKdEncryptedKey,
        vetkd_args: &VetKdArgsOwned,
        rng: &mut R,
    ) -> Result<(), VetKdKeyVerificationError> {
        let (_verifier_id, verifier) = self.random_node(rng);
        verifier.verify_encrypted_key(ek, &vetkd_args.as_ref())
    }
}

struct VetKDTestClient {
    caller: CanisterId,
    context: Vec<u8>,
    input: Vec<u8>,
    tsk: ic_vetkeys::TransportSecretKey,
    tpk: Vec<u8>,
    dk: ic_vetkeys::DerivedPublicKey,
}

impl VetKDTestClient {
    fn new<R: Rng + CryptoRng>(rng: &mut R, server: &VetKDTestServer) -> Self {
        let caller = canister_test_id(rng.r#gen::<u64>());
        let context = rng.r#gen::<[u8; 16]>().to_vec();
        let input = rng.r#gen::<[u8; 32]>().to_vec();

        let dk = server.derive_key(&caller, &context);

        let tsk = ic_vetkeys::TransportSecretKey::from_seed(rng.r#gen::<[u8; 32]>().to_vec())
            .expect("failed to create transport secret key");

        let tpk = tsk.public_key();

        Self {
            caller,
            context,
            input,
            tsk,
            tpk,
            dk,
        }
    }

    fn create_args(&self, dkg_id: &NiDkgId) -> VetKdArgsOwned {
        VetKdArgsOwned {
            ni_dkg_id: dkg_id.clone(),
            caller: self.caller.get(),
            context: self.context.clone(),
            input: self.input.clone(),
            transport_public_key: self.tpk.clone(),
        }
    }

    fn decrypt_key(&self, encrypted_key: &VetKdEncryptedKey) -> Result<Vec<u8>, String> {
        let encrypted_key = ic_vetkeys::EncryptedVetKey::deserialize(&encrypted_key.encrypted_key)?;

        Ok(encrypted_key
            .decrypt_and_verify(&self.tsk, &self.dk, &self.input)?
            .signature_bytes()
            .to_vec())
    }
}

fn wrong_ni_dkg_id(dkg_id: &NiDkgId) -> NiDkgId {
    NiDkgId {
        dealer_subnet: dkg_id.dealer_subnet,
        dkg_tag: dkg_id.dkg_tag.clone(),
        target_subnet: dkg_id.target_subnet,
        start_block_height: (dkg_id.start_block_height.get() + 1000000).into(),
    }
}

#[test]
fn should_consistently_derive_the_same_vetkey_given_sufficient_shares() {
    let mut rng = reproducible_rng();
    let server = VetKDTestServer::new(&mut rng);
    let client = VetKDTestClient::new(&mut rng, &server);
    let vetkd_args = client.create_args(&server.dkg_id);

    let mut keys = vec![];

    for _i in 0..3 {
        let shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation failed");

        assert!(
            server
                .verify_key_shares(&shares, &vetkd_args, &mut rng)
                .is_ok()
        );

        let encrypted_key = server
            .combine_key_shares(&shares, &vetkd_args, &mut rng)
            .expect("Share combination failed")
            .1;

        let decrypted_key = client
            .decrypt_key(&encrypted_key)
            .expect("Failed to decrypt key");

        keys.push(decrypted_key);
    }

    assert!(keys.iter().all(|k| *k == keys[0]));
}

mod create_encrypted_key_share {

    use super::*;

    #[test]
    fn should_err_if_threshold_sig_data_not_loaded() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let vetkd_args = client.create_args(&wrong_ni_dkg_id(&server.dkg_id));

        let shares = server.create_key_shares(&vetkd_args, &mut rng);

        match shares {
            Err(VetKdKeyShareCreationError::ThresholdSigDataNotFound(_)) => { /* expected */ }
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    fn should_err_if_transport_public_key_is_invalid() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let mut vetkd_args = client.create_args(&server.dkg_id);

        // Set the infinity bit which causes the point to become an invalid encoding
        vetkd_args.transport_public_key[0] ^= 0x40;

        let shares = server.create_key_shares(&vetkd_args, &mut rng);

        match shares {
            Err(VetKdKeyShareCreationError::InvalidArgumentEncryptionPublicKey) => { /* expected */
            }
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }
}

fn flip_random_bit<R: Rng + CryptoRng>(v: &mut [u8], rng: &mut R) {
    let idx = rng.gen_range(0..v.len());
    v[idx] ^= 1 << (rng.r#gen::<usize>() % 8);
}

fn corrupt_share_contents<R: Rng + CryptoRng>(share: &mut VetKdEncryptedKeyShare, rng: &mut R) {
    flip_random_bit(&mut share.encrypted_key_share.0, rng);
}

fn corrupt_share_signature<R: Rng + CryptoRng>(share: &mut VetKdEncryptedKeyShare, rng: &mut R) {
    flip_random_bit(&mut share.node_signature, rng);
}

fn swap_share_c1c3(share: &mut VetKdEncryptedKeyShareContent) {
    let share_len = share.0.len();
    for idx in 0..48 {
        share.0.swap(idx, share_len - 48 + idx);
    }
}

fn modify_random_share<R: Rng + CryptoRng, F: FnOnce(&mut VetKdEncryptedKeyShare, &mut R)>(
    shares: &mut BTreeMap<NodeId, VetKdEncryptedKeyShare>,
    rng: &mut R,
    modify: F,
) {
    let idx = rng.gen_range(0..shares.len());

    modify(shares.iter_mut().nth(idx).expect("Missing share").1, rng);
}

fn modify_n_random_shares<R: Rng + CryptoRng, F: Fn(&mut VetKdEncryptedKeyShare, &mut R)>(
    n: usize,
    shares: &mut BTreeMap<NodeId, VetKdEncryptedKeyShare>,
    rng: &mut R,
    modify: F,
) {
    assert!(shares.len() >= n);

    for node_id in shares.keys().copied().choose_multiple(rng, n) {
        let share = shares.get_mut(&node_id).expect("Missing share");
        modify(share, rng);
    }
}

mod verify_key_share {

    use super::*;

    #[test]
    fn should_err_with_thresholdsigdatanotfound_if_threshold_sig_data_not_loaded() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let mut vetkd_args = client.create_args(&server.dkg_id);

        let shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        vetkd_args.ni_dkg_id = wrong_ni_dkg_id(&server.dkg_id);
        match server.verify_key_shares(&shares, &vetkd_args, &mut rng) {
            Err(VetKdKeyShareVerificationError::ThresholdSigDataNotFound(_)) => { /* expected */ }
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    fn should_err_with_verificationerror_if_share_signature_is_invalid() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let vetkd_args = client.create_args(&server.dkg_id);

        let mut shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        modify_random_share(&mut shares, &mut rng, |share, rng| {
            corrupt_share_signature(share, rng)
        });

        match server.verify_key_shares(&shares, &vetkd_args, &mut rng) {
            Err(VetKdKeyShareVerificationError::VerificationError(_)) => { /* expected */ }
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }
}

mod combine_shares {

    use super::*;

    #[test]
    fn should_succeed_if_reconstruction_threshold_many_shares_are_valid() {
        let mut rng = reproducible_rng();
        let mut server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let vetkd_args = client.create_args(&server.dkg_id);

        let mut shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        let to_corrupt = shares.len() - server.config.threshold().get().get() as usize;

        modify_n_random_shares(to_corrupt, &mut shares, &mut rng, |share, _rng| {
            swap_share_c1c3(&mut share.encrypted_key_share);
        });

        match server.combine_key_shares(&shares, &vetkd_args, &mut rng) {
            Ok((combiner, _key)) => {
                /* expected success */
                let logger = server
                    .env
                    .loggers
                    .remove(&combiner)
                    .expect("Missing loggers");
                let logs = logger.drain_logs();
                LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Info,
                "EncryptedKey::combine_all failed with InvalidShares, falling back to EncryptedKey::combine_valid_shares"
            );
            }
            Err(e) => panic!("Combination failed {:?}", e),
        }
    }

    #[test]
    fn should_err_with_thresholdsigdatanotfound_if_threshold_sig_data_not_loaded() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let mut vetkd_args = client.create_args(&server.dkg_id);

        let shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        vetkd_args.ni_dkg_id = wrong_ni_dkg_id(&server.dkg_id);

        match server.combine_key_shares(&shares, &vetkd_args, &mut rng) {
            Err(VetKdKeyShareCombinationError::ThresholdSigDataNotFound(_)) => { /* expected */ }
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    fn should_err_if_reconstruction_threshold_not_met() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let vetkd_args = client.create_args(&server.dkg_id);

        let mut shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        while shares.len() >= server.config.threshold().get().get() as usize {
            if let Some(dealer) = shares
                .keys()
                .collect::<Vec<_>>()
                .into_iter()
                .cloned()
                .choose(&mut rng)
            {
                shares.remove(&dealer).expect("Removing share failed");
            }
        }

        match server.combine_key_shares(&shares, &vetkd_args, &mut rng) {
            Err(VetKdKeyShareCombinationError::UnsatisfiedReconstructionThreshold {
                threshold: _,
                share_count: _,
            }) => { /* expected */ }
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    fn should_err_if_transport_public_key_is_invalid() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let mut vetkd_args = client.create_args(&server.dkg_id);

        let shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        // Set the infinity bit which causes the point to become an invalid encoding
        vetkd_args.transport_public_key[0] ^= 0x40;

        match server.combine_key_shares(&shares, &vetkd_args, &mut rng) {
            Err(VetKdKeyShareCombinationError::InvalidArgumentEncryptionPublicKey) => { /* expected */
            }
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    fn should_err_if_some_encrypted_key_share_is_invalid() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let vetkd_args = client.create_args(&server.dkg_id);

        let mut shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        modify_random_share(&mut shares, &mut rng, |share, rng| {
            corrupt_share_contents(share, rng)
        });

        match server.combine_key_shares(&shares, &vetkd_args, &mut rng) {
            Err(VetKdKeyShareCombinationError::InvalidArgumentEncryptedKeyShare) => { /* expected */
            }
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    fn should_err_if_combination_fails_due_to_too_many_invalid_shares() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let vetkd_args = client.create_args(&server.dkg_id);

        let mut shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        /*
         * If any of the shares fails to deserialize then the combination step fails
         * immediately. We avoid this by using the structure of the share; it is c1/c2/c3
         * where c1 and c3 are in G1 and c2 is G2, and all the values are just concatenated.
         * So by swapping the first and last 48 bytes we get a valid share encoding which is
         * still invalid.
         */

        let to_corrupt = shares.len() - server.config.threshold().get().get() as usize + 1;

        modify_n_random_shares(to_corrupt, &mut shares, &mut rng, |share, _rng| {
            swap_share_c1c3(&mut share.encrypted_key_share);
        });

        match server.combine_key_shares(&shares, &vetkd_args, &mut rng) {
            Err(VetKdKeyShareCombinationError::CombinationError(_)) => { /* expected */ }
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }
}

mod verify_encrypted_key {

    use super::*;

    #[test]
    fn should_err_if_encrypted_key_is_invalid() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let vetkd_args = client.create_args(&server.dkg_id);

        let shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        let mut ek = server
            .combine_key_shares(&shares, &vetkd_args, &mut rng)
            .expect("Share combination failed")
            .1;

        assert!(
            server
                .verify_encrypted_key(&ek, &vetkd_args, &mut rng)
                .is_ok()
        );

        flip_random_bit(&mut ek.encrypted_key, &mut rng);

        match server.verify_encrypted_key(&ek, &vetkd_args, &mut rng) {
            Ok(_) => panic!("Unexpected success"),
            Err(VetKdKeyVerificationError::InvalidArgumentEncryptedKey) => {
                // expected if invalid key cannot be deserialized
            }
            Err(VetKdKeyVerificationError::VerificationError) => {
                // expected if invalid key can be deserialized
            }
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    fn should_err_with_thresholdsigdatanotfound_if_threshold_sig_data_not_loaded() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let mut vetkd_args = client.create_args(&server.dkg_id);

        let shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        let ek = server
            .combine_key_shares(&shares, &vetkd_args, &mut rng)
            .expect("Share combination failed")
            .1;

        vetkd_args.ni_dkg_id = wrong_ni_dkg_id(&vetkd_args.ni_dkg_id);

        match server.verify_encrypted_key(&ek, &vetkd_args, &mut rng) {
            Ok(_) => panic!("Unexpected success"),
            Err(VetKdKeyVerificationError::ThresholdSigDataNotFound(_)) => { /* expected */ }
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    fn should_err_with_invalidargumentencryptionpublickey_if_transport_public_key_is_invalid() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let mut vetkd_args = client.create_args(&server.dkg_id);

        let shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        let ek = server
            .combine_key_shares(&shares, &vetkd_args, &mut rng)
            .expect("Share combination failed")
            .1;

        flip_random_bit(&mut vetkd_args.transport_public_key, &mut rng);

        match server.verify_encrypted_key(&ek, &vetkd_args, &mut rng) {
            Ok(_) => panic!("Unexpected success"),
            Err(VetKdKeyVerificationError::InvalidArgumentEncryptionPublicKey) => { /* expected */ }
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    fn should_err_with_verificationerror_if_encrypted_key_is_invalid() {
        let mut rng = reproducible_rng();
        let server = VetKDTestServer::new(&mut rng);
        let client = VetKDTestClient::new(&mut rng, &server);
        let vetkd_args = client.create_args(&server.dkg_id);

        let shares = server
            .create_key_shares(&vetkd_args, &mut rng)
            .expect("Share creation unexpectedly failed");

        let mut ek = server
            .combine_key_shares(&shares, &vetkd_args, &mut rng)
            .expect("Share combination failed")
            .1;

        let g1_bytes = ic_crypto_internal_bls12_381_vetkd::G1Affine::generator().serialize();
        ek.encrypted_key[0..48].copy_from_slice(&g1_bytes);

        match server.verify_encrypted_key(&ek, &vetkd_args, &mut rng) {
            Ok(_) => panic!("Unexpected success"),
            Err(VetKdKeyVerificationError::VerificationError) => { /* expected */ }
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }
}

/////////////////////////////////////////////////////////////////////////////////
// The following helper functions where copied from threshold_sigs_with_ni_dkg.rs
/////////////////////////////////////////////////////////////////////////////////

fn load_transcript_for_receivers_expecting_status<C: CryptoComponentRng>(
    config: &NiDkgConfig,
    transcript: &NiDkgTranscript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
    expected_status: Option<LoadTranscriptResult>,
) {
    for node_id in config.receivers().get() {
        let result = crypto_for(*node_id, crypto_components).load_transcript(transcript);

        match result {
            Ok(status) => {
                if let Some(expected_status) = expected_status {
                    assert_eq!(status, expected_status);
                }
            }
            Err(err) => {
                panic!(
                    "failed to load transcript {} for node {}: {}",
                    transcript, *node_id, err
                );
            }
        }
    }
}

fn random_node_in<R: Rng + CryptoRng>(nodes: &BTreeSet<NodeId>, rng: &mut R) -> NodeId {
    *nodes.iter().choose(rng).expect("nodes empty")
}
