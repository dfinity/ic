use ic_crypto_internal_bls12_381_type::{
    verify_bls_signature, G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Polynomial, Scalar,
};
use ic_crypto_internal_bls12_381_vetkd::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{prelude::SliceRandom, CryptoRng, Rng, RngCore, SeedableRng};

#[derive(Copy, Clone, Debug)]
/// Deserialization of a transport secret key failed
pub enum TransportSecretKeyDeserializationError {
    /// Error indicating the key was not a valid scalar
    InvalidSecretKey,
}

#[derive(Clone)]
/// Secret key of the transport key pair
pub struct TransportSecretKey {
    secret_key: Scalar,
}

impl TransportSecretKey {
    /// The length of the serialized encoding of this type
    pub const BYTES: usize = Scalar::BYTES;

    /// Create a new transport secret key
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = Scalar::random(rng);
        Self { secret_key }
    }

    /// Serialize the transport secret key to a bytestring
    pub fn serialize(&self) -> [u8; Self::BYTES] {
        self.secret_key.serialize()
    }

    /// Deserialize a previously serialized transport secret key
    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransportSecretKeyDeserializationError> {
        let secret_key = Scalar::deserialize(&bytes)
            .map_err(|_| TransportSecretKeyDeserializationError::InvalidSecretKey)?;
        Ok(Self { secret_key })
    }

    /// Return the public key associated with this secret key
    pub fn public_key(&self) -> TransportPublicKey {
        let public_key = G1Affine::generator() * &self.secret_key;
        let pk_bytes = public_key.to_affine().serialize();
        TransportPublicKey::deserialize(&pk_bytes).expect("Invalid public key")
    }

    fn secret(&self) -> &Scalar {
        &self.secret_key
    }

    /// Decrypt an encrypted key
    ///
    /// Returns None if decryption failed
    pub fn decrypt(
        &self,
        ek: &EncryptedKey,
        dpk: &DerivedPublicKey,
        did: &[u8],
    ) -> Option<G1Affine> {
        let msg = G1Affine::augmented_hash(dpk.point(), did);

        let k = G1Affine::from(G1Projective::from(ek.c3()) - ek.c1() * self.secret());

        let dpk_prep = G2Prepared::from(dpk.point());
        let k_is_valid_sig =
            Gt::multipairing(&[(&k, G2Prepared::neg_generator()), (&msg, &dpk_prep)]).is_identity();

        if k_is_valid_sig {
            Some(k)
        } else {
            None
        }
    }
}

#[test]
fn transport_key_gen_is_stable() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0);
    let tsk = TransportSecretKey::generate(&mut rng);

    assert_eq!(
        hex::encode(tsk.serialize()),
        "32f7f581d6de3c06a822fd6e7e8265fbc00f8401696a5bdc34f5a6d2ff3f922f"
    );

    assert_eq!(hex::encode(tsk.public_key().serialize()),
               "ac9524f219f1f958f261c87577e49dbbf2182c4060d51f84b8a0efac33c3c7ba9cd0bc9f41edf434d6c8a8fe20077e50");
}

fn random_derivation_path<R: RngCore + CryptoRng>(rng: &mut R) -> DerivationPath {
    let canister_id = rng.gen::<[u8; 32]>();

    let num_extra = rng.gen::<usize>() % 16;

    let extra_paths = {
        let mut ep = vec![];
        for _ in 0..num_extra {
            let path_len = rng.gen::<usize>() % 24;

            let mut path = vec![0u8; path_len];
            rng.fill_bytes(&mut path);
            ep.push(path);
        }
        ep
    };

    DerivationPath::new(&canister_id, &extra_paths)
}

fn shake256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut shake = ic_sha3::Shake256::new();
    shake.update(bytes);
    let mut xof_reader = shake.finalize_xof();
    xof_reader.read(&mut output);
    output
}

#[test]
fn encrypted_key_share_creation_is_stable() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);

    let tpk = TransportSecretKey::generate(&mut rng).public_key();

    const NODES: usize = 13;
    let threshold = 3;

    let poly = Polynomial::random(threshold, &mut rng);

    let master_sk = poly.coeff(0);
    let master_pk = G2Affine::from(G2Affine::generator() * master_sk);

    let derivation_path = random_derivation_path(&mut rng);
    let did = rng.gen::<[u8; 28]>();

    const EXPECTED_EKS_HASH: [&str; NODES] = [
        "cb3075ecd2c5cd946dcfaf8486031cf7bbca656092aada97644307c598af5073",
        "fbfaa432bd0fc9c60b456742368034d35d5fefceae1cdd027c27147ecc7f012c",
        "7d6bd8ef201443fe5b570b62d244fc8192819f53783a1ae81e3fe747a793decd",
        "12f894d3ddce41e5fa0cb1cd05e77d50ed214248cba809a9fe6fccf5515f5c13",
        "d187e7bf4defab92ce9c82c692a9b3c3de65994cd4bf422438cbc515a8a48501",
        "9aa47ad2dcf06a6a308152d935698684799714c772dfaf2b6654e6642a11937b",
        "d96c4f897ba7e7ac657d363171b324adbad2faf13ef395bd0efa28a60273583d",
        "fc3b2d0eae4c7d96212058d815d48701267a673c20197a08f28762301043405d",
        "85ba21972c3a7717922d6bc734217d5dae12be7df42ffb93604e0ae7228ac9ed",
        "3f7b6c16d35118519c92d31e074633f00fe30b6e4b522cda47d81088dc4011bb",
        "658383824de7771db64a87b884ffbefe92567baeb851229785d9f3717c91bdda",
        "e7a69b641278a5a8084938d1c03de2850a6639a882713a190fe0417f678e118e",
        "d59283b0a48181d93c6e1a22e5ff9130df68a01bcadf96a25d37a2a092cb1a1a",
    ];

    for (node_idx, expected_eks_hash) in EXPECTED_EKS_HASH.iter().enumerate() {
        let node_sk = poly.evaluate_at(&Scalar::from_node_index(node_idx as u32));
        let eks =
            EncryptedKeyShare::create(&mut rng, &master_pk, &node_sk, &tpk, &derivation_path, &did);
        assert_eq!(hex::encode(shake256(&eks.serialize())), *expected_eks_hash,);
    }
}

struct VetkdTestProtocolSetup {
    nodes: usize,
    threshold: usize,
    transport_sk: TransportSecretKey,
    transport_pk: TransportPublicKey,
    master_pk: G2Affine,
    node_key_material: Vec<(G2Affine, Scalar)>,
}

impl VetkdTestProtocolSetup {
    fn new<R: Rng + CryptoRng>(rng: &mut R, nodes: usize, threshold: usize) -> Self {
        let transport_sk = TransportSecretKey::generate(rng);
        let transport_pk = transport_sk.public_key();

        // In production this is done using a DKG...
        let poly = Polynomial::random(threshold, rng);

        let master_sk = poly.coeff(0);
        let master_pk = G2Affine::from(G2Affine::generator() * master_sk);

        let mut node_key_material = Vec::with_capacity(nodes);

        for node in 0..nodes {
            let node_sk = poly.evaluate_at(&Scalar::from_node_index(node as u32));
            let node_pk = G2Affine::from(G2Affine::generator() * &node_sk);
            node_key_material.push((node_pk, node_sk));
        }

        Self {
            nodes,
            threshold,
            transport_sk,
            transport_pk,
            master_pk,
            node_key_material,
        }
    }
}

struct VetkdTestProtocolExecution<'a> {
    setup: &'a VetkdTestProtocolSetup,
    did: Vec<u8>,
    derivation_path: DerivationPath,
    derived_pk: DerivedPublicKey,
}

impl<'a> VetkdTestProtocolExecution<'a> {
    fn new<R: Rng + CryptoRng>(
        rng: &mut R,
        setup: &'a VetkdTestProtocolSetup,
    ) -> VetkdTestProtocolExecution<'a> {
        let did = rng.gen::<[u8; 32]>().to_vec();
        let derivation_path = random_derivation_path(rng);

        let derived_pk = DerivedPublicKey::compute_derived_key(&setup.master_pk, &derivation_path);

        Self {
            setup,
            did,
            derivation_path,
            derived_pk,
        }
    }

    fn create_encrypted_key_shares<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        did: Option<&[u8]>,
    ) -> Vec<(u32, G2Affine, EncryptedKeyShare)> {
        let mut node_info = Vec::with_capacity(self.setup.nodes);

        let did = did.unwrap_or(&self.did);

        for (node_idx, (node_pk, node_sk)) in self.setup.node_key_material.iter().enumerate() {
            let eks = EncryptedKeyShare::create(
                rng,
                &self.setup.master_pk,
                node_sk,
                &self.setup.transport_pk,
                &self.derivation_path,
                did,
            );

            assert!(eks.is_valid(
                &self.setup.master_pk,
                node_pk,
                &self.derivation_path,
                did,
                &self.setup.transport_pk
            ));

            // check that EKS serialization round trips:
            let eks_bytes = eks.serialize();
            let eks2 = EncryptedKeyShare::deserialize(&eks_bytes).unwrap();
            assert_eq!(eks, eks2);

            node_info.push((node_idx as u32, node_pk.clone(), eks.clone()));
        }

        node_info
    }

    fn combine_all(
        &self,
        node_eks: &[(u32, EncryptedKeyShare)],
    ) -> Result<EncryptedKey, EncryptedKeyCombinationError> {
        EncryptedKey::combine_all(
            node_eks,
            self.setup.threshold,
            &self.setup.master_pk,
            &self.setup.transport_pk,
            &self.derivation_path,
            &self.did,
        )
    }

    fn combine_valid(
        &self,
        node_info: &[(u32, G2Affine, EncryptedKeyShare)],
    ) -> Result<EncryptedKey, EncryptedKeyCombinationError> {
        EncryptedKey::combine_valid_shares(
            node_info,
            self.setup.threshold,
            &self.setup.master_pk,
            &self.setup.transport_pk,
            &self.derivation_path,
            &self.did,
        )
    }
}

fn random_subset<R: rand::Rng, T: Clone>(rng: &mut R, items: &[T], include: usize) -> Vec<T> {
    use rand::seq::SliceRandom;

    assert!(include <= items.len());
    let result: Vec<_> = items.choose_multiple(rng, include).cloned().collect();
    assert_eq!(result.len(), include);

    result
}

#[test]
fn test_protocol_execution() {
    let rng = &mut reproducible_rng();

    let nodes = 31;
    let threshold = 11;

    let setup = VetkdTestProtocolSetup::new(rng, nodes, threshold);
    let proto = VetkdTestProtocolExecution::new(rng, &setup);

    let node_info = proto.create_encrypted_key_shares(rng, None);

    let node_eks = node_info
        .iter()
        .map(|(idx, _pk, eks)| (*idx, eks.clone()))
        .collect::<Vec<_>>();

    let mut keys_recovered = vec![];

    // Check that recovery works with sufficient shares, and fails without sufficient shares
    for rec_threshold in 1..nodes {
        if let Ok(ek) = proto.combine_all(&random_subset(rng, &node_eks, rec_threshold)) {
            assert!(
                rec_threshold >= threshold,
                "Recovery only works with sufficient quorum"
            );

            assert!(ek.is_valid(
                &setup.master_pk,
                &proto.derivation_path,
                &proto.did,
                &setup.transport_pk
            ));

            let k = setup
                .transport_sk
                .decrypt(&ek, &proto.derived_pk, &proto.did)
                .expect("Decryption failed");

            keys_recovered.push(k);
        } else {
            assert!(
                rec_threshold < threshold,
                "Recovery fails with insufficient quorum"
            );
        }
    }

    // Now check that each recovered vetkey is the same:
    let vetkey = keys_recovered[0].clone();

    for k in &keys_recovered {
        assert_eq!(*k, vetkey);
    }

    // Check that the vetkey output is a valid BLS signature
    let msg = G1Affine::augmented_hash(proto.derived_pk.point(), &proto.did);

    assert!(verify_bls_signature(
        &vetkey,
        proto.derived_pk.point(),
        &msg
    ));

    // Check that if we introduce incorrect shares then combine_all will fail

    let other_did = rng.gen::<[u8; 24]>();
    assert_ne!(proto.did, other_did);
    let node_info_wrong_did = proto.create_encrypted_key_shares(rng, Some(&other_did));

    let node_eks_wrong_did = node_info_wrong_did
        .iter()
        .map(|(idx, _pk, eks)| (*idx, eks.clone()))
        .collect::<Vec<_>>();

    // With combine_all even if we provide sufficiently many valid shares
    // if any one share is invalid then combination will fail
    for rec_threshold in 2..nodes {
        let mut shares = random_subset(rng, &node_eks, rec_threshold - 1);

        // Avoid using a duplicate index for this test
        let random_unused_idx = loop {
            let idx = (rng.gen::<usize>() % node_eks_wrong_did.len()) as u32;
            if !shares.iter().map(|(i, _eks)| *i).any(|x| x == idx) {
                break idx as usize;
            }
        };

        shares.push(node_eks_wrong_did[random_unused_idx].clone());
        shares.shuffle(rng);

        let expected_error = if rec_threshold < threshold {
            EncryptedKeyCombinationError::InsufficientShares
        } else {
            EncryptedKeyCombinationError::InvalidShares
        };
        assert_eq!(proto.combine_all(&shares), Err(expected_error));
    }

    // Check that duplicate node indexes are detected
    for rec_threshold in 2..nodes {
        let mut shares = random_subset(rng, &node_eks, rec_threshold - 1);

        let random_duplicate_idx = loop {
            let idx = (rng.gen::<usize>() % node_eks.len()) as u32;

            if shares.iter().map(|(i, _eks)| *i).any(|x| x == idx) {
                break idx as usize;
            }
        };

        shares.push(node_eks[random_duplicate_idx].clone());
        shares.shuffle(rng);

        let expected_error = if rec_threshold < threshold {
            EncryptedKeyCombinationError::InsufficientShares
        } else {
            EncryptedKeyCombinationError::DuplicateNodeIndex
        };
        assert_eq!(proto.combine_all(&shares), Err(expected_error));
    }

    // With combine_valid_shares OTOH we detect and reject the invalid shares

    for rec_threshold in threshold..nodes {
        let mut shares = random_subset(rng, &node_info, rec_threshold);
        shares.append(&mut random_subset(rng, &node_info_wrong_did, 4));
        shares.shuffle(rng);

        let combined = proto.combine_valid(&shares);
        assert!(combined.is_ok(), "Combination unexpectedly failed");

        let k = setup
            .transport_sk
            .decrypt(
                &combined.expect("Already checked"),
                &proto.derived_pk,
                &proto.did,
            )
            .expect("Decryption failed");

        assert_eq!(k, vetkey);
    }

    // Here check that if we add a random duplicate (valid) share to the
    // list, combine_valid succeeds iff the duplicated share does not
    // appear in the first `threshold` many shares, since we only look
    // at that many
    for rec_threshold in threshold..nodes {
        let mut shares = random_subset(rng, &node_info, rec_threshold);

        let random_duplicate_idx = loop {
            let idx = (rng.gen::<usize>() % node_eks.len()) as u32;

            if shares.iter().map(|x| x.0).any(|x| x == idx) {
                break idx as usize;
            }
        };

        shares.push(node_info[random_duplicate_idx].clone());
        shares.shuffle(rng);

        let result = proto.combine_valid(&shares);

        if result.is_ok() {
            // This can still suceed since we only look at the first threshold shares
            // If success, verify that the duplicate appears later in the list

            let indexes = shares
                .iter()
                .map(|s| s.0)
                .enumerate()
                .filter(|(_i, s)| *s == random_duplicate_idx as u32)
                .map(|s| s.0)
                .collect::<Vec<usize>>();
            assert_eq!(indexes.len(), 2);
            assert!(indexes[1] >= threshold);
        } else {
            assert_eq!(
                result,
                Err(EncryptedKeyCombinationError::DuplicateNodeIndex)
            );
        }
    }
}
