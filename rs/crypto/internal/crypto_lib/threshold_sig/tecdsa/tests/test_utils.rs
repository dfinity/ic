#![allow(dead_code)]

use ic_types::crypto::canister_threshold_sig::MasterEcdsaPublicKey;
use ic_types::crypto::AlgorithmId;
use ic_types::*;
use rand::Rng;
use std::collections::BTreeMap;
use tecdsa::*;

#[derive(Debug, Clone)]
pub struct ProtocolSetup {
    alg: AlgorithmId,
    threshold: NumberOfNodes,
    receivers: usize,
    ad: Vec<u8>,
    pk: Vec<MEGaPublicKey>,
    sk: Vec<MEGaPrivateKey>,
    seed: Seed,
    protocol_round: std::cell::Cell<usize>,
}

impl ProtocolSetup {
    pub fn new(
        curve: EccCurveType,
        receivers: usize,
        threshold: usize,
        seed: Seed,
    ) -> Result<Self, ThresholdEcdsaError> {
        let alg = match curve {
            EccCurveType::K256 => AlgorithmId::ThresholdEcdsaSecp256k1,
            _ => {
                return Err(ThresholdEcdsaError::InvalidArguments(
                    "Unsupported curve".to_string(),
                ))
            }
        };

        let mut rng = seed.into_rng();
        let ad = rng.gen::<[u8; 32]>().to_vec();

        let mut sk = Vec::with_capacity(receivers);
        let mut pk = Vec::with_capacity(receivers);

        for _i in 0..receivers {
            let k = MEGaPrivateKey::generate(curve, &mut rng)?;
            pk.push(k.public_key()?);
            sk.push(k);
        }

        let threshold = NumberOfNodes::from(threshold as u32);

        Ok(Self {
            alg,
            threshold,
            receivers,
            ad,
            pk,
            sk,
            seed: Seed::from_rng(&mut rng),
            protocol_round: std::cell::Cell::new(0),
        })
    }

    pub fn next_dealing_seed(&self) -> Seed {
        let round = self.protocol_round.get();

        let seed = self
            .seed
            .derive(&format!("ic-crypto-tecdsa-round-{}", round));

        self.protocol_round.set(round + 1);

        seed
    }

    pub fn remove_nodes(&mut self, removing: usize) {
        assert!(self.receivers >= removing);

        self.receivers -= removing;

        while self.pk.len() != self.receivers {
            self.pk.pop();
        }
        while self.sk.len() != self.receivers {
            self.sk.pop();
        }
    }

    pub fn modify_threshold(&mut self, threshold: usize) {
        self.threshold = NumberOfNodes::from(threshold as u32);
    }

    pub fn receiver_info(&self) -> Vec<(MEGaPrivateKey, MEGaPublicKey, NodeIndex)> {
        let mut info = Vec::with_capacity(self.receivers);
        for i in 0..self.receivers {
            info.push((self.sk[i].clone(), self.pk[i], i as NodeIndex));
        }
        info
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolRound {
    pub commitment: PolynomialCommitment,
    pub transcript: IDkgTranscriptInternal,
    pub openings: Vec<CommitmentOpening>,
    pub dealings: BTreeMap<NodeIndex, IDkgDealingInternal>,
}

impl ProtocolRound {
    // Internal constructor
    pub fn new(
        setup: &ProtocolSetup,
        dealings: BTreeMap<NodeIndex, IDkgDealingInternal>,
        transcript: IDkgTranscriptInternal,
    ) -> Self {
        let openings = Self::open_dealings(setup, &dealings, &transcript);
        let commitment = transcript.combined_commitment.commitment().clone();
        assert!(Self::verify_commitment_openings(&commitment, &openings).is_ok());

        Self {
            commitment,
            transcript,
            openings,
            dealings,
        }
    }

    /// Runs a `ProtocolRound` for a `Random` transcript with `number_of_dealers` many
    /// distinct dealers.
    ///
    /// If `number_of_dealings_corrupted` is > 0 then some number of the dealings
    /// with be randomly corrupted.
    pub fn random(
        setup: &ProtocolSetup,
        number_of_dealers: usize,
        number_of_dealings_corrupted: usize,
    ) -> ThresholdEcdsaResult<Self> {
        let shares = vec![SecretShares::Random; number_of_dealers as usize];
        let mode = IDkgTranscriptOperationInternal::Random;

        let dealings = Self::create_dealings(
            setup,
            &shares,
            number_of_dealers,
            number_of_dealings_corrupted,
            &mode,
            setup.next_dealing_seed(),
        );
        let transcript = Self::create_transcript(setup, &dealings, &mode)?;

        match transcript.combined_commitment {
            CombinedCommitment::BySummation(PolynomialCommitment::Pedersen(_)) => {}
            _ => panic!("Unexpected transcript commitment type"),
        }

        Ok(Self::new(setup, dealings, transcript))
    }

    /// Runs a `ProtocolRound` for a `ReshareOfMasked` transcript with `number_of_dealers`
    /// many distinct dealers.
    ///
    /// If `number_of_dealings_corrupted` is > 0 then some number of the dealings
    /// with be randomly corrupted.
    pub fn reshare_of_masked(
        setup: &ProtocolSetup,
        masked: &ProtocolRound,
        number_of_dealers: usize,
        number_of_dealings_corrupted: usize,
    ) -> ThresholdEcdsaResult<Self> {
        let mut shares = Vec::with_capacity(masked.openings.len());
        for opening in &masked.openings {
            match opening {
                CommitmentOpening::Pedersen(v, m) => {
                    shares.push(SecretShares::ReshareOfMasked(*v, *m));
                }
                _ => panic!("Unexpected opening type"),
            }
        }

        let mode = IDkgTranscriptOperationInternal::ReshareOfMasked(masked.commitment.clone());

        let dealings = Self::create_dealings(
            setup,
            &shares,
            number_of_dealers,
            number_of_dealings_corrupted,
            &mode,
            setup.next_dealing_seed(),
        );
        let transcript = Self::create_transcript(setup, &dealings, &mode)?;

        match transcript.combined_commitment {
            CombinedCommitment::ByInterpolation(PolynomialCommitment::Simple(_)) => {}
            _ => panic!("Unexpected transcript commitment type"),
        }

        Ok(Self::new(setup, dealings, transcript))
    }

    /// Runs a `ProtocolRound` for a `ReshareOfUnmasked` transcript with
    /// `number_of_dealers` many distinct dealers.
    ///
    /// If `number_of_dealings_corrupted` is > 0 then some number of the dealings
    /// with be randomly corrupted.
    pub fn reshare_of_unmasked(
        setup: &ProtocolSetup,
        unmasked: &ProtocolRound,
        number_of_dealers: usize,
        number_of_dealings_corrupted: usize,
    ) -> ThresholdEcdsaResult<Self> {
        let mut shares = Vec::with_capacity(unmasked.openings.len());
        for opening in &unmasked.openings {
            match opening {
                CommitmentOpening::Simple(v) => {
                    shares.push(SecretShares::ReshareOfUnmasked(*v));
                }
                _ => panic!("Unexpected opening type"),
            }
        }

        let mode = IDkgTranscriptOperationInternal::ReshareOfUnmasked(unmasked.commitment.clone());

        let dealings = Self::create_dealings(
            setup,
            &shares,
            number_of_dealers,
            number_of_dealings_corrupted,
            &mode,
            setup.next_dealing_seed(),
        );
        let transcript = Self::create_transcript(setup, &dealings, &mode)?;

        match transcript.combined_commitment {
            CombinedCommitment::ByInterpolation(PolynomialCommitment::Simple(_)) => {}
            _ => panic!("Unexpected transcript commitment type"),
        }

        // The two commitments are both simple, so we can verify shared value
        assert_eq!(
            transcript.combined_commitment.commitment().constant_term(),
            unmasked.constant_term()
        );

        Ok(Self::new(setup, dealings, transcript))
    }

    /// Runs a `ProtocolRound` for a `UnmaskedTimesMasked` transcript with
    /// `number_of_dealers` many distinct dealers.
    ///
    /// If `number_of_dealings_corrupted` is > 0 then some number of the dealings
    /// with be randomly corrupted.
    pub fn multiply(
        setup: &ProtocolSetup,
        masked: &ProtocolRound,
        unmasked: &ProtocolRound,
        number_of_dealers: usize,
        number_of_dealings_corrupted: usize,
    ) -> ThresholdEcdsaResult<Self> {
        let mut shares = Vec::with_capacity(unmasked.openings.len());
        for opening in unmasked.openings.iter().zip(masked.openings.iter()) {
            match opening {
                (CommitmentOpening::Simple(lhs_v), CommitmentOpening::Pedersen(rhs_v, rhs_m)) => {
                    shares.push(SecretShares::UnmaskedTimesMasked(*lhs_v, (*rhs_v, *rhs_m)))
                }
                _ => panic!("Unexpected opening type"),
            }
        }

        let mode = IDkgTranscriptOperationInternal::UnmaskedTimesMasked(
            unmasked.commitment.clone(),
            masked.commitment.clone(),
        );

        let dealings = Self::create_dealings(
            setup,
            &shares,
            number_of_dealers,
            number_of_dealings_corrupted,
            &mode,
            setup.next_dealing_seed(),
        );
        let transcript = Self::create_transcript(setup, &dealings, &mode)?;

        match transcript.combined_commitment {
            CombinedCommitment::ByInterpolation(PolynomialCommitment::Pedersen(_)) => {}
            _ => panic!("Unexpected transcript commitment type"),
        }

        Ok(Self::new(setup, dealings, transcript))
    }

    /// Verified that parties holding secret `openings` can reconstruct the
    /// opening of the constant term of `commitment`.
    fn verify_commitment_openings(
        commitment: &PolynomialCommitment,
        openings: &[CommitmentOpening],
    ) -> ThresholdEcdsaResult<()> {
        let constant_term = commitment.constant_term();
        let curve_type = constant_term.curve_type();

        match commitment {
            PolynomialCommitment::Simple(_) => {
                let mut g_openings = Vec::with_capacity(openings.len());

                for (idx, opening) in openings.iter().enumerate() {
                    if let CommitmentOpening::Simple(value) = opening {
                        let index = EccScalar::from_node_index(curve_type, idx as NodeIndex);
                        g_openings.push((index, *value));
                    } else {
                        panic!("Unexpected opening type");
                    }
                }

                let dlog = EccScalar::interpolation_at_zero(&g_openings)?;
                let pt = EccPoint::mul_by_g(&dlog)?;
                assert_eq!(pt, constant_term);
            }

            PolynomialCommitment::Pedersen(_) => {
                let mut g_openings = Vec::with_capacity(openings.len());
                let mut h_openings = Vec::with_capacity(openings.len());

                for (idx, opening) in openings.iter().enumerate() {
                    if let CommitmentOpening::Pedersen(value, mask) = opening {
                        let index = EccScalar::from_node_index(curve_type, idx as NodeIndex);
                        g_openings.push((index, *value));
                        h_openings.push((index, *mask));
                    } else {
                        panic!("Unexpected opening type");
                    }
                }

                let dlog_g = EccScalar::interpolation_at_zero(&g_openings)?;
                let dlog_h = EccScalar::interpolation_at_zero(&h_openings)?;
                let pt = EccPoint::pedersen(&dlog_g, &dlog_h)?;
                assert_eq!(pt, constant_term);
            }
        }

        Ok(())
    }

    /// Reconstruct the secret shares for all receivers in a given transcript.
    fn open_dealings(
        setup: &ProtocolSetup,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        transcript: &IDkgTranscriptInternal,
    ) -> Vec<CommitmentOpening> {
        let mut openings = Vec::with_capacity(setup.receivers);

        // Ensure every receiver can open
        for receiver in 0..setup.receivers {
            let opening = compute_secret_shares(
                dealings,
                transcript,
                &setup.ad,
                receiver as NodeIndex,
                &setup.sk[receiver],
                &setup.pk[receiver],
            );

            if let Ok(opening) = opening {
                openings.push(opening);
            } else {
                // Generate a complaint:
                let complaints = generate_complaints(
                    dealings,
                    &setup.ad,
                    receiver as NodeIndex,
                    &setup.sk[receiver],
                    &setup.pk[receiver],
                    setup.next_dealing_seed(),
                )
                .expect("Unable to generate complaints");

                let mut provided_openings = BTreeMap::new();

                for (dealer_index, complaint) in &complaints {
                    let dealing = dealings.get(dealer_index).unwrap();
                    // the complaints must be valid
                    assert!(complaint
                        .verify(
                            dealing,
                            *dealer_index,
                            receiver as NodeIndex, /* complainer index */
                            &setup.pk[receiver],
                            &setup.ad
                        )
                        .is_ok());

                    let mut openings_for_this_dealing = BTreeMap::new();

                    // create openings in response to the complaints
                    for opener in 0..setup.receivers {
                        if opener == receiver {
                            continue;
                        }

                        let dopening = open_dealing(
                            dealing,
                            &setup.ad,
                            *dealer_index,
                            opener as NodeIndex,
                            &setup.sk[opener],
                            &setup.pk[opener],
                        )
                        .expect("Unable to open dealing");

                        // The openings must be valid:
                        assert!(
                            verify_dealing_opening(dealing, opener as NodeIndex, &dopening).is_ok()
                        );

                        openings_for_this_dealing.insert(opener as NodeIndex, dopening);
                    }

                    provided_openings.insert(*dealer_index, openings_for_this_dealing);
                }

                let opening = compute_secret_shares_with_openings(
                    dealings,
                    &provided_openings,
                    transcript,
                    &setup.ad,
                    receiver as NodeIndex,
                    &setup.sk[receiver],
                    &setup.pk[receiver],
                )
                .expect("Unable to open dealing using provided openings");

                openings.push(opening);
            }
        }

        assert_eq!(
            openings.len(),
            setup.receivers,
            "Expected number of openings"
        );
        openings
    }

    fn create_transcript(
        setup: &ProtocolSetup,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        mode: &IDkgTranscriptOperationInternal,
    ) -> ThresholdEcdsaResult<IDkgTranscriptInternal> {
        match create_transcript(setup.alg, setup.threshold, dealings, mode) {
            Ok(t) => Ok(t),
            Err(IDkgCreateTranscriptInternalError::InsufficientDealings) => {
                Err(ThresholdEcdsaError::InsufficientDealings)
            }
            Err(IDkgCreateTranscriptInternalError::InconsistentCommitments) => {
                Err(ThresholdEcdsaError::InconsistentCommitments)
            }
            Err(_) => panic!("Unexpected error from create_transcript"),
        }
    }

    /// Create dealings generated by `number_of_dealers` random dealers.
    fn create_dealings(
        setup: &ProtocolSetup,
        shares: &[SecretShares],
        number_of_dealers: usize,
        number_of_dealings_corrupted: usize,
        transcript_type: &IDkgTranscriptOperationInternal,
        seed: Seed,
    ) -> BTreeMap<NodeIndex, IDkgDealingInternal> {
        assert!(number_of_dealers <= shares.len());
        assert!(number_of_dealings_corrupted <= number_of_dealers);

        let mut rng = seed.into_rng();

        let mut dealings = BTreeMap::new();

        let number_of_receivers = NumberOfNodes::from(setup.receivers as u32);

        for (dealer_index, share) in shares.iter().enumerate() {
            let dealing_randomness = Randomness::from(rng.gen::<[u8; 32]>());
            let dealer_index = dealer_index as u32;

            let dealing = create_dealing(
                setup.alg,
                &setup.ad,
                dealer_index,
                setup.threshold,
                &setup.pk,
                share,
                dealing_randomness,
            )
            .expect("failed to create dealing");

            let publicly_invalid = publicly_verify_dealing(
                setup.alg,
                &dealing,
                transcript_type,
                setup.threshold,
                dealer_index,
                number_of_receivers,
                &setup.ad,
            )
            .is_err();

            if publicly_invalid {
                panic!("Created a publicly invalid dealing");
            }

            for (private_key, public_key, recipient_index) in setup.receiver_info() {
                let locally_invalid = privately_verify_dealing(
                    setup.alg,
                    &dealing,
                    &private_key,
                    &public_key,
                    &setup.ad,
                    dealer_index,
                    recipient_index,
                )
                .is_err();

                if locally_invalid {
                    panic!("Created a locally invalid dealing");
                }
            }

            dealings.insert(dealer_index, dealing);
        }

        // Discard some of the dealings at random
        while dealings.len() > number_of_dealers {
            let index = rng.gen::<usize>() % shares.len();
            dealings.remove(&(index as u32));
        }

        if number_of_dealings_corrupted > 0 {
            let mut damaged_dealings = std::collections::BTreeSet::new();
            while damaged_dealings.len() != number_of_dealings_corrupted {
                let index = rng.gen::<usize>() % setup.receivers;

                if dealings.contains_key(&(index as u32)) {
                    damaged_dealings.insert(index);
                }
            }

            for i in damaged_dealings {
                let corrupted_recip = rng.gen::<usize>() % setup.receivers;

                let dealing = dealings.get(&(i as u32)).unwrap();
                let bad_dealing =
                    test_utils::corrupt_dealing(dealing, &[corrupted_recip as NodeIndex], &mut rng)
                        .unwrap();

                // replace the dealing with a corrupted one
                dealings.insert(i as NodeIndex, bad_dealing);
            }
        }

        dealings
    }

    pub fn constant_term(&self) -> EccPoint {
        self.commitment.constant_term()
    }
}

#[derive(Clone, Debug)]
pub struct SignatureProtocolSetup {
    setup: ProtocolSetup,
    pub key: ProtocolRound,
    pub kappa: ProtocolRound,
    pub lambda: ProtocolRound,
    pub key_times_lambda: ProtocolRound,
    pub kappa_times_lambda: ProtocolRound,
}

impl SignatureProtocolSetup {
    pub fn new(
        curve: EccCurveType,
        number_of_dealers: usize,
        threshold: usize,
        seed: Seed,
    ) -> ThresholdEcdsaResult<Self> {
        let setup = ProtocolSetup::new(curve, number_of_dealers, threshold, seed)?;

        let number_of_dealings_corrupted = threshold;

        let key = ProtocolRound::random(&setup, number_of_dealers, number_of_dealings_corrupted)?;
        let kappa = ProtocolRound::random(&setup, number_of_dealers, number_of_dealings_corrupted)?;
        let lambda =
            ProtocolRound::random(&setup, number_of_dealers, number_of_dealings_corrupted)?;

        let key = ProtocolRound::reshare_of_masked(
            &setup,
            &key,
            number_of_dealers,
            number_of_dealings_corrupted,
        )?;
        let kappa = ProtocolRound::reshare_of_masked(
            &setup,
            &kappa,
            number_of_dealers,
            number_of_dealings_corrupted,
        )?;

        let key_times_lambda = ProtocolRound::multiply(
            &setup,
            &lambda,
            &key,
            number_of_dealers,
            number_of_dealings_corrupted,
        )?;
        let kappa_times_lambda = ProtocolRound::multiply(
            &setup,
            &lambda,
            &kappa,
            number_of_dealers,
            number_of_dealings_corrupted,
        )?;

        Ok(Self {
            setup,
            key,
            kappa,
            lambda,
            key_times_lambda,
            kappa_times_lambda,
        })
    }

    pub fn public_key(&self, path: &DerivationPath) -> Result<EcdsaPublicKey, ThresholdEcdsaError> {
        let master_public_key = MasterEcdsaPublicKey {
            algorithm_id: AlgorithmId::EcdsaSecp256k1,
            public_key: self.key.transcript.constant_term().serialize(),
        };
        tecdsa::sign::derive_public_key(&master_public_key, path)
    }
}

#[derive(Clone, Debug)]
pub struct SignatureProtocolExecution {
    setup: SignatureProtocolSetup,
    signed_message: Vec<u8>,
    hashed_message: Vec<u8>,
    random_beacon: Randomness,
    derivation_path: DerivationPath,
}

impl SignatureProtocolExecution {
    pub fn new(
        setup: SignatureProtocolSetup,
        signed_message: Vec<u8>,
        random_beacon: Randomness,
        derivation_path: DerivationPath,
    ) -> Self {
        let hashed_message = ic_crypto_sha::Sha256::hash(&signed_message).to_vec();

        Self {
            setup,
            signed_message,
            hashed_message,
            random_beacon,
            derivation_path,
        }
    }

    pub fn generate_shares(
        &self,
    ) -> ThresholdEcdsaResult<BTreeMap<u32, ThresholdEcdsaSigShareInternal>> {
        let mut shares = BTreeMap::new();

        for node_index in 0..self.setup.setup.receivers {
            let share = sign_share(
                &self.derivation_path,
                &self.hashed_message,
                self.random_beacon,
                &self.setup.key.transcript,
                &self.setup.kappa.transcript,
                &self.setup.lambda.openings[node_index],
                &self.setup.kappa_times_lambda.openings[node_index],
                &self.setup.key_times_lambda.openings[node_index],
                self.setup.setup.alg,
            )
            .expect("Failed to create sig share");

            verify_signature_share(
                &share,
                &self.derivation_path,
                &self.hashed_message,
                self.random_beacon,
                node_index as u32,
                &self.setup.key.transcript,
                &self.setup.kappa.transcript,
                &self.setup.lambda.transcript,
                &self.setup.kappa_times_lambda.transcript,
                &self.setup.key_times_lambda.transcript,
                self.setup.setup.alg,
            )
            .expect("Signature share verification failed");

            shares.insert(node_index as NodeIndex, share);
        }

        Ok(shares)
    }

    pub fn generate_signature(
        &self,
        shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
    ) -> Result<ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaCombineSigSharesInternalError>
    {
        combine_sig_shares(
            &self.derivation_path,
            &self.hashed_message,
            self.random_beacon,
            &self.setup.key.transcript,
            &self.setup.kappa.transcript,
            self.setup.setup.threshold,
            shares,
            self.setup.setup.alg,
        )
    }

    pub fn verify_signature(
        &self,
        sig: &ThresholdEcdsaCombinedSigInternal,
    ) -> Result<(), ThresholdEcdsaVerifySignatureInternalError> {
        verify_threshold_signature(
            sig,
            &self.derivation_path,
            &self.hashed_message,
            self.random_beacon,
            &self.setup.kappa.transcript,
            &self.setup.key.transcript,
            self.setup.setup.alg,
        )?;

        // If verification succeeded, check with RustCrypto's ECDSA also
        let pk = self.setup.public_key(&self.derivation_path)?;

        use k256::ecdsa::signature::{Signature, Verifier};

        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk.public_key)
            .expect("Failed to parse public key");

        let sig = k256::ecdsa::Signature::from_bytes(&sig.serialize())
            .expect("Failed to parse signature");

        assert!(vk.verify(&self.signed_message, &sig).is_ok());

        Ok(())
    }
}

pub fn random_seed() -> Seed {
    let mut rng = rand::thread_rng();
    Seed::from_rng(&mut rng)
}
