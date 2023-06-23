use ic_crypto_internal_bls12_381_vetkd::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, RngCore};

/// A Polynomial whose coefficients are scalars in an elliptic curve group
///
/// The coefficients are stored in little-endian ordering, ie a_0 is
/// self.coefficients\[0\]
#[derive(Clone, Debug)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Eq for Polynomial {}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        // Accept leading zero elements
        let max_coef = std::cmp::max(self.coefficients.len(), other.coefficients.len());

        for i in 0..max_coef {
            if self.coeff(i) != other.coeff(i) {
                return false;
            }
        }

        true
    }
}

impl Polynomial {
    pub fn new(coefficients: Vec<Scalar>) -> Self {
        Self { coefficients }
    }

    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Self::new(vec![])
    }

    /// Creates a random polynomial with the specified number of coefficients
    fn random<R: CryptoRng + RngCore>(num_coefficients: usize, rng: &mut R) -> Self {
        let mut coefficients = Vec::with_capacity(num_coefficients);

        for _ in 0..num_coefficients {
            coefficients.push(Scalar::random(rng))
        }

        Self { coefficients }
    }

    fn coeff(&self, idx: usize) -> Scalar {
        match self.coefficients.get(idx) {
            Some(s) => s.clone(),
            None => Scalar::zero(),
        }
    }

    fn evaluate_at(&self, x: &Scalar) -> Scalar {
        if self.coefficients.is_empty() {
            return Scalar::zero();
        }

        let mut coefficients = self.coefficients.iter().rev();
        let mut ans = coefficients
            .next()
            .expect("Iterator was unexpectedly empty")
            .clone();

        for coeff in coefficients {
            ans *= x;
            ans += coeff;
        }
        ans
    }
}

#[test]
fn should_encrypted_key_share_be_functional() {
    let derivation_path = DerivationPath::new(b"canister-id", &[b"1", b"2"]);
    let did = b"message";

    let mut rng = reproducible_rng();

    let nodes = 31;
    let threshold = 11;

    let poly = Polynomial::random(threshold + 1, &mut rng);

    let tsk = TransportSecretKey::generate(&mut rng);
    let tpk = tsk.public_key();
    //let (tpk, tsk) = transport_keygen(&mut rng);

    let master_sk = poly.coeff(0);
    let master_pk = G2Affine::from(G2Affine::generator() * &master_sk);

    let dpk = DerivedPublicKey::compute_derived_key(&master_pk, &derivation_path);

    let mut node_info = Vec::with_capacity(nodes);

    for node in 0..nodes {
        let node_sk = poly.evaluate_at(&Scalar::from_node_index(node as u32));
        let node_pk = G2Affine::from(G2Affine::generator() * &node_sk);

        let eks =
            EncryptedKeyShare::create(&mut rng, &master_pk, &node_sk, &tpk, &derivation_path, did);

        assert!(eks.is_valid(&master_pk, &node_pk, &derivation_path, did, &tpk));

        // check that EKS serialization round trips:
        let eks_bytes = eks.serialize();
        let eks2 = EncryptedKeyShare::deserialize(eks_bytes).unwrap();
        assert_eq!(eks, eks2);

        node_info.push((node as u32, node_pk, eks));
    }

    let ek = EncryptedKey::combine(
        &node_info,
        threshold,
        &master_pk,
        &tpk,
        &derivation_path,
        did,
    )
    .unwrap();

    let k = tsk.decrypt(&ek, &dpk, did).unwrap();

    let derived_key = tsk
        .decrypt_and_hash(&ek, &dpk, did, 32, b"aes-256-gcm-siv")
        .unwrap();
    assert_eq!(derived_key.len(), 32);

    let msg = b"is this thing on?";
    let ctext = IBECiphertext::encrypt(&dpk, did, msg, &mut rng);
    let ctext_bytes = ctext.serialize();

    let ctext = IBECiphertext::deserialize(&ctext_bytes).unwrap();
    let recovered = ctext.decrypt(&k).unwrap();

    assert_eq!(recovered, msg);
}

fn random_node_indexes<R: rand::Rng>(rng: &mut R, count: usize) -> Vec<NodeIndex> {
    let mut set = std::collections::BTreeSet::new();

    while set.len() != count {
        let r = rng.gen::<NodeIndex>();
        set.insert(r);
    }

    set.iter().cloned().collect()
}

#[test]
fn should_g1_interpolation_at_zero_work() -> Result<(), LagrangeError> {
    let mut rng = reproducible_rng();

    for num_coefficients in 1..30 {
        let poly = Polynomial::random(num_coefficients, &mut rng);

        let sk = poly.coeff(0);
        let pk = G1Affine::from(G1Affine::generator() * &sk);

        let node_ids = random_node_indexes(&mut rng, num_coefficients);
        let mut node_shares = Vec::with_capacity(num_coefficients);

        for r in &node_ids {
            let p_r = poly.evaluate_at(&Scalar::from_node_index(*r));
            let g_p_r = G1Affine::from(G1Affine::generator() * &p_r);
            node_shares.push(g_p_r);
        }

        let coefficients = LagrangeCoefficients::at_zero(&node_ids)?;
        let g0 = coefficients.interpolate_g1(&node_shares)?;
        assert_eq!(g0, pk);
    }

    Ok(())
}

#[test]
fn should_g2_interpolation_at_zero_work() -> Result<(), LagrangeError> {
    let mut rng = reproducible_rng();

    for num_coefficients in 1..30 {
        let poly = Polynomial::random(num_coefficients, &mut rng);

        let sk = poly.coeff(0);
        let pk = G2Affine::from(G2Affine::generator() * &sk);

        let node_ids = random_node_indexes(&mut rng, num_coefficients);
        let mut node_shares = Vec::with_capacity(num_coefficients);

        for r in &node_ids {
            let p_r = poly.evaluate_at(&Scalar::from_node_index(*r));
            let g_p_r = G2Affine::from(G2Affine::generator() * &p_r);
            node_shares.push(g_p_r);
        }

        let coefficients = LagrangeCoefficients::at_zero(&node_ids)?;
        let g0 = coefficients.interpolate_g2(&node_shares)?;
        assert_eq!(g0, pk);
    }

    Ok(())
}
