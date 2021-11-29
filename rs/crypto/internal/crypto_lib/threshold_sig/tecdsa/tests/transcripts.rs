use ic_types::crypto::AlgorithmId;
use ic_types::*;
use rand::Rng;
use std::collections::BTreeMap;
use tecdsa::*;

struct ProtocolSetup {
    alg: AlgorithmId,
    threshold: NumberOfNodes,
    receivers: usize,
    ad: Vec<u8>,
    pk: Vec<MEGaPublicKey>,
    sk: Vec<MEGaPrivateKey>,
}

impl ProtocolSetup {
    fn new(
        curve: EccCurveType,
        receivers: usize,
        threshold: usize,
    ) -> Result<Self, ThresholdEcdsaError> {
        let alg = match curve {
            EccCurveType::K256 => AlgorithmId::ThresholdEcdsaSecp256k1,
            _ => {
                return Err(ThresholdEcdsaError::InvalidArguments(
                    "Unsupported curve".to_string(),
                ))
            }
        };

        let mut rng = rand::thread_rng();
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
        })
    }

    fn remove_nodes(&mut self, removing: usize) {
        assert!(self.receivers >= removing);

        self.receivers -= removing;

        while self.pk.len() != self.receivers {
            self.pk.pop();
        }
        while self.sk.len() != self.receivers {
            self.sk.pop();
        }
    }

    fn modify_threshold(&mut self, threshold: usize) {
        self.threshold = NumberOfNodes::from(threshold as u32);
    }
}

#[derive(Debug)]
struct ProtocolRound {
    pub commitment: PolynomialCommitment,
    pub openings: Vec<CommitmentOpening>,
}

impl ProtocolRound {
    // Internal constructor
    fn new(
        setup: &ProtocolSetup,
        dealings: BTreeMap<NodeIndex, IDkgDealingInternal>,
        transcript: IDkgTranscriptInternal,
    ) -> Self {
        let openings = Self::open_dealings(setup, &dealings, &transcript);
        let commitment = transcript.combined_commitment.commitment().clone();
        assert!(Self::verify_commitment_openings(&commitment, &openings).is_ok());

        Self {
            commitment,
            openings,
        }
    }

    /// Runs a `ProtocolRound` for a `Random` transcript with `dealers` many
    /// distinct dealers.
    fn random(setup: &ProtocolSetup, dealers: usize) -> ThresholdEcdsaResult<Self> {
        let shares = vec![SecretShares::Random; dealers as usize];
        let mode = IDkgTranscriptOperationInternal::Random;

        let dealings = Self::create_dealings(setup, &shares, dealers);
        let transcript = Self::create_transcript(setup, &dealings, &mode)?;

        match transcript.combined_commitment {
            CombinedCommitment::BySummation(PolynomialCommitment::Pedersen(_)) => {}
            _ => panic!("Unexpected transcript commitment type"),
        }

        Ok(Self::new(setup, dealings, transcript))
    }

    /// Runs a `ProtocolRound` for a `ReshareOfMasked` transcript with `dealers`
    /// many distinct dealers.
    fn reshare_of_masked(
        setup: &ProtocolSetup,
        masked: &ProtocolRound,
        dealers: usize,
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

        let dealings = Self::create_dealings(setup, &shares, dealers);
        let transcript = Self::create_transcript(setup, &dealings, &mode)?;

        match transcript.combined_commitment {
            CombinedCommitment::ByInterpolation(PolynomialCommitment::Simple(_)) => {}
            _ => panic!("Unexpected transcript commitment type"),
        }

        Ok(Self::new(setup, dealings, transcript))
    }

    /// Runs a `ProtocolRound` for a `ReshareOfUnmasked` transcript with
    /// `dealers` many distinct dealers.
    fn reshare_of_unmasked(
        setup: &ProtocolSetup,
        unmasked: &ProtocolRound,
        dealers: usize,
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

        let dealings = Self::create_dealings(setup, &shares, dealers);
        let transcript = Self::create_transcript(setup, &dealings, &mode)?;

        match transcript.combined_commitment {
            CombinedCommitment::ByInterpolation(PolynomialCommitment::Simple(_)) => {}
            _ => panic!("Unexpected transcript commitment type"),
        }

        Ok(Self::new(setup, dealings, transcript))
    }

    /// Runs a `ProtocolRound` for a `UnmaskedTimesMasked` transcript with
    /// `dealers` many distinct dealers.
    fn multiply(
        setup: &ProtocolSetup,
        masked: &ProtocolRound,
        unmasked: &ProtocolRound,
        dealers: usize,
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

        let dealings = Self::create_dealings(setup, &shares, dealers);
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
        let curve = EccCurve::new(curve_type);

        match commitment {
            PolynomialCommitment::Simple(_) => {
                let mut g_openings = Vec::with_capacity(openings.len());

                for (idx, opening) in openings.iter().enumerate() {
                    if let CommitmentOpening::Simple(value) = opening {
                        let index = EccScalar::from_u64(curve_type, idx as u64 + 1);
                        g_openings.push((index, *value));
                    } else {
                        panic!("Unexpected opening type");
                    }
                }

                let dlog = EccScalar::interpolation_at_zero(&g_openings)?;
                let pt = dlog.curve().generator_g()?.scalar_mul(&dlog)?;
                assert_eq!(pt, constant_term);
            }

            PolynomialCommitment::Pedersen(_) => {
                let mut g_openings = Vec::with_capacity(openings.len());
                let mut h_openings = Vec::with_capacity(openings.len());

                for (idx, opening) in openings.iter().enumerate() {
                    if let CommitmentOpening::Pedersen(value, mask) = opening {
                        let index = EccScalar::from_u64(curve_type, idx as u64 + 1);
                        g_openings.push((index, *value));
                        h_openings.push((index, *mask));
                    } else {
                        panic!("Unexpected opening type");
                    }
                }

                let dlog_g = EccScalar::interpolation_at_zero(&g_openings)?;
                let dlog_h = EccScalar::interpolation_at_zero(&h_openings)?;
                let pt_g = curve.generator_g()?.scalar_mul(&dlog_g)?;
                let pt_h = curve.generator_h()?.scalar_mul(&dlog_h)?;
                let pt = pt_g.add_points(&pt_h)?;
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
            )
            .expect("unable to compute secret shares");

            openings.push(opening);
        }

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

    /// Create dealings generated by `dealings_returned` random dealers.
    fn create_dealings(
        setup: &ProtocolSetup,
        shares: &[SecretShares],
        dealings_returned: usize,
    ) -> BTreeMap<NodeIndex, IDkgDealingInternal> {
        let mut rng = rand::thread_rng();

        let mut dealings = BTreeMap::new();

        for (dealer_index, share) in shares.iter().enumerate() {
            let dealing_randomness = Randomness::from(rng.gen::<[u8; 32]>());
            let dealing = create_dealing(
                setup.alg,
                &setup.ad,
                dealer_index as u32,
                setup.threshold,
                &setup.pk,
                share,
                dealing_randomness,
            )
            .expect("failed to create dealing");

            dealings.insert(dealer_index as u32, dealing);
        }

        // Potentially remove some of the dealings at random
        while dealings.len() > dealings_returned {
            let index = rng.gen::<usize>() % shares.len();
            dealings.remove(&(index as u32));
        }

        dealings
    }

    fn constant_term(&self) -> EccPoint {
        self.commitment.constant_term()
    }
}

fn insufficient_dealings(r: Result<ProtocolRound, ThresholdEcdsaError>) {
    match r {
        Err(ThresholdEcdsaError::InsufficientDealings) => {}
        Err(e) => panic!("Unexpected error {:?}", e),
        Ok(r) => panic!("Unexpected success {:?}", r),
    }
}

#[test]
fn should_reshare_transcripts_correctly() -> Result<(), ThresholdEcdsaError> {
    let setup = ProtocolSetup::new(EccCurveType::K256, 4, 2)?;

    // First create a transcript of random dealings
    let random = ProtocolRound::random(&setup, 4)?;

    // Now reshare the random value twice

    // 1 dealing is not sufficient
    insufficient_dealings(ProtocolRound::reshare_of_masked(&setup, &random, 1));

    // 2, 3, or 4 works:
    let reshared2 = ProtocolRound::reshare_of_masked(&setup, &random, 2)?;
    let reshared3 = ProtocolRound::reshare_of_masked(&setup, &random, 3)?;
    let reshared4 = ProtocolRound::reshare_of_masked(&setup, &random, 4)?;

    // The same value is committed in the resharings despite different dealing cnt
    assert_eq!(reshared2.constant_term(), reshared3.constant_term());
    assert_eq!(reshared2.constant_term(), reshared4.constant_term());

    // Now reshare the now-unmasked value
    insufficient_dealings(ProtocolRound::reshare_of_unmasked(&setup, &reshared2, 1));
    let unmasked = ProtocolRound::reshare_of_unmasked(&setup, &reshared2, 2)?;
    assert_eq!(reshared2.constant_term(), unmasked.constant_term());

    // Now multiply the masked and umasked values
    // We need 3 dealings to multiply
    insufficient_dealings(ProtocolRound::multiply(&setup, &random, &unmasked, 1));
    insufficient_dealings(ProtocolRound::multiply(&setup, &random, &unmasked, 2));
    let _product = ProtocolRound::multiply(&setup, &random, &unmasked, 3)?;

    Ok(())
}

#[test]
fn should_multiply_trasncripts_correctly() -> Result<(), ThresholdEcdsaError> {
    let setup = ProtocolSetup::new(EccCurveType::K256, 4, 2)?;

    let dealers = 4;

    // First create two random transcripts
    let random_a = ProtocolRound::random(&setup, dealers)?;
    let random_b = ProtocolRound::random(&setup, dealers)?;

    // Now reshare them both
    let random_c = ProtocolRound::reshare_of_masked(&setup, &random_a, dealers)?;
    let random_d = ProtocolRound::reshare_of_masked(&setup, &random_b, dealers)?;

    // Now multiply A*D and B*C (which will be the same numbers)
    let product_ad = ProtocolRound::multiply(&setup, &random_a, &random_d, dealers)?;
    let product_bc = ProtocolRound::multiply(&setup, &random_b, &random_c, dealers)?;

    // Now reshare AD and BC
    let reshare_ad = ProtocolRound::reshare_of_masked(&setup, &product_ad, dealers)?;
    let reshare_bc = ProtocolRound::reshare_of_masked(&setup, &product_bc, dealers)?;

    // The committed values of AD and BC should be the same:
    assert_eq!(reshare_ad.constant_term(), reshare_bc.constant_term());

    Ok(())
}

#[test]
fn should_reshare_transcripts_with_dynamic_threshold() -> Result<(), ThresholdEcdsaError> {
    let mut setup = ProtocolSetup::new(EccCurveType::K256, 5, 2)?;

    let random_a = ProtocolRound::random(&setup, 5)?;

    insufficient_dealings(ProtocolRound::reshare_of_masked(&setup, &random_a, 1));
    let reshared_b = ProtocolRound::reshare_of_masked(&setup, &random_a, 2)?;

    setup.modify_threshold(1);
    setup.remove_nodes(2);
    insufficient_dealings(ProtocolRound::reshare_of_unmasked(&setup, &reshared_b, 1));

    let reshared_c = ProtocolRound::reshare_of_unmasked(&setup, &reshared_b, 2)?;
    let reshared_d = ProtocolRound::reshare_of_unmasked(&setup, &reshared_b, 3)?;

    // b, c, and d all have the same value
    assert_eq!(reshared_b.constant_term(), reshared_c.constant_term());
    assert_eq!(reshared_b.constant_term(), reshared_d.constant_term());

    Ok(())
}

#[test]
fn should_multiply_transcripts_with_dynamic_threshold() -> Result<(), ThresholdEcdsaError> {
    let mut setup = ProtocolSetup::new(EccCurveType::K256, 5, 2)?;

    let random_a = ProtocolRound::random(&setup, 5)?;
    let random_b = ProtocolRound::random(&setup, 5)?;

    let reshared_c = ProtocolRound::reshare_of_masked(&setup, &random_a, 3)?;

    setup.modify_threshold(1);
    setup.remove_nodes(2);
    insufficient_dealings(ProtocolRound::multiply(&setup, &random_b, &reshared_c, 1));
    insufficient_dealings(ProtocolRound::multiply(&setup, &random_b, &reshared_c, 2));

    let _product = ProtocolRound::multiply(&setup, &random_b, &reshared_c, 3)?;

    Ok(())
}
