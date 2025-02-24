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

    const EXPECTED_EKS_VALUE: [&str; NODES] = [
        "a9940d0137c71275b4d11bf9a80bcf484a93e777a20734b95dd57e835ac484661f4056bbd4fa3ed218f50d967617c2b781516e7bd2baace117b77803686953aaebba83589a10a15b7a139da6dc3f1093561ccce5ded1ad7bfed4e35a198a0a0e14936d6a37ebba930bfae338185ac104c4ef67f899c0cc25467f80f09a886574dbc0642a6ed1a2516d4f7c90c9128610ae6d24d5bea60cdc939f5ebe2a98ce274cbb57003db162bac370a255eeab6ba1ff639d19fe97d61045a671162b15fe60",
"b9d2a21b758fc961c8a98dc7aa5a5597bcbc365134d3da90527a6b60a30831803afd52fc5e0163c5fd43154c0d2177f49317ddf48515edd84ccf2ecd8724f808b24ca44f10a684cdc4eb56f23c2f2a5152c44cbb59a0c70155aecda3f95710770582abdf6febb54b078a90b96af6fb1b27073dd10cd5366e1e6ce378d882b7251f361d4979388d0a8efe288811adb3b5a24f833bdb6fa7dda962970410ab4364c2a837781176187fa62ff51841f81a8f6bbea3e7b171ebb93d4ce11bd9be7b4d",
"811d9cd064cd7c6ab4a448c68b8b5fc8a5f08cd17c78d46469e810e8df3d1f8d3f1431ccf627e2198b72d850eb99b2e2b2dfe2c43ddf86e5403ba474a3a0ba596ddabecfe303eddfd70444057baaae733f92eca70509425f87633ce9d78a28040b559446e22f73d637b04c6eca6ecff71fb3d1a662d86ef22fa6c3ef8157c582e4afdc7a0047d4535c6e01e9c65eae7890de3f7362e9d027f847484e5e3a2734c57f02030c44425012f17277c825d8093bef8862bd69753c7ac0d80b45c4257c",
"aca469bb1dd96297c86044e6032c15fbf2a2c380764085be21d50cff4b9f52f5e32e8c7fd718d64b435334b4aa9f8016a4dbcedc7da27a8b23d4b254850a26e75cb7e744585f0bcf5fb4b7ffb7befa0a983cbff9de8d22be23f6674a32fd058a03f31140af7af5934a23ef4494fe1bd2ff3947dae35f4bc653388878fdea0a451d7bdd1ecaabec217faa1efcf24dd5a68aaae8ce07882503721cbbb0a6afed9bdfe611b6e6f70cf1f36300d296d97c284bdc1c06f2fad6c3b9b3f2bed39f6f6d",
"abc9b461b441ce17b4d581f5a82f0f21dfb0091c9c097e2f4ce7962adf7c14d14d86c9765dc2e296c66a02187699fbe396767f7fdbe594a787368bb59ef5d43b70bd0c7a39e07b27107cdc7fb06de7da15a2a33cd10593b65764c98a7591726a0f603451396769fdaf5bd3b69ff0b7f515b4fd1dd0629b3762bc3916b8c2e01d2bfd5ddebc9f638191cc919da5a5d619864bc64eaa58a9af0a48487c12040619f1d45e5c42959b7cc89e036caeb207e9e33def185af6b4f11c06ba9d7505b800",
"92ef0d8f00e18f23879783c51c72b9706c7ad0df2a2ba44d651c5c3d903431ca49732637a579eb8c423e2b79faf9fb0b95fb96958149013e2932286ccf93bcbb94386df13e0519927b231a39f9a40b82bcd7fea94490e574493fa38a7a809a2211f4f2296639157bfe932518a5b4d8ccee3ac4997dce11aab4ff31633f715c1b1c3a6cc3a9ee14b879d0c890721d0e3f833c9383b01a183c11076f08c6e70fa1d4e14189878614ba5c49631f013f2b680ec56d582bf1ca5ac17a96bee0c80925",
"8efef76050abe03984f8b22b1cd6075a89e361c8f70bd2b493185d710ff284cca2d32c41d05735f5d9f39a4ea9b5e2cb8b4b207ec0d535c835768f95a0a1e13018b185b77f6e506fe85c2014989113b2c59935f2e323db5913bdddff8b56aa5a000a6f4e4c409a9ead3945979e3914e903b75bf754587ffbcead720960dfbcb6407d193acc91734cf61ef47d8b8684c59575f5590e3a5cc065f065f9adf4e30cbf6fe3f2469eeacb0c8baae349f86f1c0d0ac6dafb600c7a8feb05cbd8490fb5",
"80ac9ea725ec6101b18e316e7f8ff9cdbf7619549b5b9cea767203deb4b0e0496c1c84e828e74268d2368937e7f9a34195b3697321df62a084bcc2cc2bf079ce2638625bbf243d906130a700908ce481dbbe1d32b014e89baef97cc10aa6f914092a904efd5d904a1ed3687361a186126858f14bc84cdd00cc0c4671313874f1ebedf1bddc3bb3d0484e23dfc754a6768b55ea732ff9c02a374c8e1fef793c01b37c464099a2863cb4c15469c4d867083db6924fb4cceda762d10a01777cdc97",
"92b3a643f608fd4ccbb7644cbb1b38ac39a6cb4461846c6cf79c3610a411fd4e8709b960260966586f67e2e0d6cf6c5b85b45c442c3f78bda0666389631a8a8c8b1c642eaa4c0214781c6ada600fd1a7663b43b844a6f7a96741315674090b7f10534d4789de9fc1829b7a97f30dedd86b8f801ac01c1f8a8e1fb247cec9f726dabe43a6f246e7248b8a6675370c47318a3c4788b4eb5092b283f7f81f6a5903c35f024159b8fc5bd2a01a4dc118b1855bcbd409abe6d54bc3daaf795694a580",
"807e2fa6fe3e4bec12953acc2b57bf4cd49614cfbccb393bbaa4a04d614f1b85a7bbae48ed5c147e05786a7a29494c2092cfd5bd41d088213fa676abd137ad6e4511ff65811c7622068d995c1d38e36f5a90284c7a5769510c1e71fb46bace121742873aa75b1956f331d13e7541fdd862d617965ed541376598a541bf2bc47e370f728e86c909b943b1db0cf6e38dba8b4ef50a2cb42410b5ccd9c2788a49df08585284c4dadeb7ff93befe0beb46ca998041ece1dd36832e5e44783f0e6005",
"b90e01a902b1af0a9039d32b1325c030424791d2a7c72dbb68cf17c962b80e2897b29bccf1bda9587f62d019098938b1b68aaf0628576dd28569de2bbc705ac51ae9e69552e912894b47d87d3af588466ad30316de574dd7663129ee342c949f101501911075cb27af2255635e9ea68401ccda1edf127ec3472d1018b0e1a012d352849ef40b835ab5357785798bbd15a90db5211cc61dd44b1660a6a2d68deb708d772b8b32fa29e9c5890ffd812709913c0488c159fe44bb8582677d171950",
"b653a21c480fccfb9b69419240cdb530e18f23b8a2bc5296073e8bea44f49104172158f2e2deec0cc1f6ed44d667bab5ab0cabfb9bd23b775fc903c2d2ddb3874c522c54e3465ed7ebbb8cec4f3e0bbca5537c8e4792a4bd0ce0e81196c49e14046ea5482f08f760d3be6b524a86f81771934cc91e1f6ed5aafc38f236ae74eba2d3d21458c0d19907b762a8fa2b860dac60873dda48bca15a4363b1271354e6623438ca5075e19a6f967c4912d8ce193e3f1f9de3f20c26a4d3bc2f7041b319",
"8489576ac848031c6e90ad9e0477fc72e766ccf00894db8ae9536415d817a4478726e4e1247ffa8656209a23ca261fa088312490c4d7b4f029f9b944196e4e3f1eb52c6a89e1ba9fc87f42c09ed3ae1490d10cdbda013863c775f00f3d070de413af98b3b688a397ab4124bc316876a4c015059607040c9faed27191db1e875e072c923fb4575f771cdb70f4ef0fbd7390b77f611ca8840b31d5d353a0039b011fc798ba380c99ed00ab4a3fedba0ded56dd630655431784d1a02767f44bfa85",
    ];

    for (node_idx, expected_eks) in EXPECTED_EKS_VALUE.iter().enumerate() {
        let node_sk = poly.evaluate_at(&Scalar::from_node_index(node_idx as u32));
        let eks =
            EncryptedKeyShare::create(&mut rng, &master_pk, &node_sk, &tpk, &derivation_path, &did);
        assert_eq!(*expected_eks, hex::encode(eks.serialize()));
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
