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
        input: &[u8],
    ) -> Option<G1Affine> {
        let msg = G1Affine::augmented_hash(dpk.point(), input);

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

fn random_derivation_context<R: RngCore + CryptoRng>(rng: &mut R) -> DerivationContext {
    let canister_id = rng.gen::<[u8; 32]>();
    let context = rng.gen::<[u8; 32]>();

    DerivationContext::new(&canister_id, &context)
}

#[test]
fn key_derivation_outputs_expected_values() {
    let mpk = DerivedPublicKey::deserialize(&hex::decode("9183b871aa141d15ba2efc5bc58a49cb6a167741364804617f48dfe11e0285696b7018f172dad1a87ed81abf27ea4c320995041e2ee4a47b2226a2439d92a38557a7e2acc72fd157283b20f1f37ba872be235214c6a9cbba1eb2ef39deec72a5").unwrap()).unwrap().point().clone();

    let canister_id = b"test-canister-id";

    let context1 = DerivationContext::new(canister_id, &[]);
    assert_eq!(hex::encode(DerivedPublicKey::compute_derived_key(&mpk, &context1).serialize()),
               "8bf165ea580742abf5fd5123eb848aa116dcf75c3ddb3cd3540c852cf99f0c5394e72dfc2f25dbcb5f9220f251cd04040a508a0bcb8b2543908d6626b46f09d614c924c5deb63a9949338ae4f4ac436bd77f8d0a392fd29de0f392a009fa61f3");

    let context = b"test-context";

    let context2 = DerivationContext::new(canister_id, context);
    assert_eq!(hex::encode(DerivedPublicKey::compute_derived_key(&mpk, &context2).serialize()),
               "9784a7db548f0271d7e35abf3bda4021d8a5993c7736bfe3cc8304d35f77441c0618bb47b53694e04a33382668a96012155cae5b0e48d586475a7148bc648a13ba680b847a2853a438a557c5e6ab2d430c8a5213042918145277aaa7c1ff75e2");
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

    let context = random_derivation_context(&mut rng);
    let input = rng.gen::<[u8; 28]>();

    const EXPECTED_EKS_VALUE: [&str; NODES] = [
        "811d9cd064cd7c6ab4a448c68b8b5fc8a5f08cd17c78d46469e810e8df3d1f8d3f1431ccf627e2198b72d850eb99b2e2b2dfe2c43ddf86e5403ba474a3a0ba596ddabecfe303eddfd70444057baaae733f92eca70509425f87633ce9d78a28040b559446e22f73d637b04c6eca6ecff71fb3d1a662d86ef22fa6c3ef8157c582e4afdc7a0047d4535c6e01e9c65eae78b2fd3c10078bac9d1c57348139f021362a3e3e48e37290fa07ed2eb502af07536c0b39b4f98c3c02c9c6c1abc0228f74",
"aca469bb1dd96297c86044e6032c15fbf2a2c380764085be21d50cff4b9f52f5e32e8c7fd718d64b435334b4aa9f8016a4dbcedc7da27a8b23d4b254850a26e75cb7e744585f0bcf5fb4b7ffb7befa0a983cbff9de8d22be23f6674a32fd058a03f31140af7af5934a23ef4494fe1bd2ff3947dae35f4bc653388878fdea0a451d7bdd1ecaabec217faa1efcf24dd5a68b891df0a7df3256aa6e42ed2892450229838e7a511431768736c14c6715a58cd68ae689df2d899b662842658026a7bd",
"abc9b461b441ce17b4d581f5a82f0f21dfb0091c9c097e2f4ce7962adf7c14d14d86c9765dc2e296c66a02187699fbe396767f7fdbe594a787368bb59ef5d43b70bd0c7a39e07b27107cdc7fb06de7da15a2a33cd10593b65764c98a7591726a0f603451396769fdaf5bd3b69ff0b7f515b4fd1dd0629b3762bc3916b8c2e01d2bfd5ddebc9f638191cc919da5a5d61988990a9c57a7ff63fa4fdc727ca7db153aa5ac5d911cbfe5b3b6557090eb6733054866c2e9a419b5493e80c6294db161",
"92ef0d8f00e18f23879783c51c72b9706c7ad0df2a2ba44d651c5c3d903431ca49732637a579eb8c423e2b79faf9fb0b95fb96958149013e2932286ccf93bcbb94386df13e0519927b231a39f9a40b82bcd7fea94490e574493fa38a7a809a2211f4f2296639157bfe932518a5b4d8ccee3ac4997dce11aab4ff31633f715c1b1c3a6cc3a9ee14b879d0c890721d0e3fb58ec134e05c8c922a96c5a44e4d75e5d5b2b7a50222cf90b05ab847a3d632d5d24c26606ea69f494d9515ec44ffdfcc",
"8efef76050abe03984f8b22b1cd6075a89e361c8f70bd2b493185d710ff284cca2d32c41d05735f5d9f39a4ea9b5e2cb8b4b207ec0d535c835768f95a0a1e13018b185b77f6e506fe85c2014989113b2c59935f2e323db5913bdddff8b56aa5a000a6f4e4c409a9ead3945979e3914e903b75bf754587ffbcead720960dfbcb6407d193acc91734cf61ef47d8b8684c591918f451f86b074cb9aa2759fe6a48b2fbac8de9aa3016a5e146663f32ee98263577228217e5a00d61838e606972098",
"80ac9ea725ec6101b18e316e7f8ff9cdbf7619549b5b9cea767203deb4b0e0496c1c84e828e74268d2368937e7f9a34195b3697321df62a084bcc2cc2bf079ce2638625bbf243d906130a700908ce481dbbe1d32b014e89baef97cc10aa6f914092a904efd5d904a1ed3687361a186126858f14bc84cdd00cc0c4671313874f1ebedf1bddc3bb3d0484e23dfc754a676a1be9db0b3532ec1b4798a9f616bc18b888b80025f7b33df0ada3729ba68f2e2097bfed17997708c9143e270d7654f75",
"92b3a643f608fd4ccbb7644cbb1b38ac39a6cb4461846c6cf79c3610a411fd4e8709b960260966586f67e2e0d6cf6c5b85b45c442c3f78bda0666389631a8a8c8b1c642eaa4c0214781c6ada600fd1a7663b43b844a6f7a96741315674090b7f10534d4789de9fc1829b7a97f30dedd86b8f801ac01c1f8a8e1fb247cec9f726dabe43a6f246e7248b8a6675370c4731aa68cfc3ad3a0357510618ca48b4c509d92b6427438ad07353fbc868a85a04d7a4b1adf65d6bfaa7fcece7217dd27b3d",
"807e2fa6fe3e4bec12953acc2b57bf4cd49614cfbccb393bbaa4a04d614f1b85a7bbae48ed5c147e05786a7a29494c2092cfd5bd41d088213fa676abd137ad6e4511ff65811c7622068d995c1d38e36f5a90284c7a5769510c1e71fb46bace121742873aa75b1956f331d13e7541fdd862d617965ed541376598a541bf2bc47e370f728e86c909b943b1db0cf6e38dbab909272120421f1312038c54829e62758935408bc4369ed2db6951ee926135485a8262c1dd5b35202c1a3baa61618069",
"b90e01a902b1af0a9039d32b1325c030424791d2a7c72dbb68cf17c962b80e2897b29bccf1bda9587f62d019098938b1b68aaf0628576dd28569de2bbc705ac51ae9e69552e912894b47d87d3af588466ad30316de574dd7663129ee342c949f101501911075cb27af2255635e9ea68401ccda1edf127ec3472d1018b0e1a012d352849ef40b835ab5357785798bbd15933adb417fb0fab32cfcc26465484bb0fe879756b3841113d8c3e61babe5189909ed523002ad6a21d8b534e1b83e6b0c",
"b653a21c480fccfb9b69419240cdb530e18f23b8a2bc5296073e8bea44f49104172158f2e2deec0cc1f6ed44d667bab5ab0cabfb9bd23b775fc903c2d2ddb3874c522c54e3465ed7ebbb8cec4f3e0bbca5537c8e4792a4bd0ce0e81196c49e14046ea5482f08f760d3be6b524a86f81771934cc91e1f6ed5aafc38f236ae74eba2d3d21458c0d19907b762a8fa2b860d8c65eaa42ce4de689fab1bb08355ed84154ca2e3bf193d2f27b4c18cf60e6767a323c9f19e15ca0f70ae110ced640463",
"8489576ac848031c6e90ad9e0477fc72e766ccf00894db8ae9536415d817a4478726e4e1247ffa8656209a23ca261fa088312490c4d7b4f029f9b944196e4e3f1eb52c6a89e1ba9fc87f42c09ed3ae1490d10cdbda013863c775f00f3d070de413af98b3b688a397ab4124bc316876a4c015059607040c9faed27191db1e875e072c923fb4575f771cdb70f4ef0fbd73b257c80458579e3f937f9f949253c6f56618f18d3a95b0274da8c90f419afdccdb134b9af1234e37845af749701b0202",
"87bfe03641974e967fb16ebeb7a571c5723c932bbe43620a81844e86857173b2800927111338080e8b33033b9253810b82a51763af54e9e05427740320aaedc813df05a17a572673502a331d5a243e4aa23bd1b49c09031c3618740f83ae3e7d0193dd05fdf4c198f88e68b7610f18667ffc547c8f432e530657f3be3ab383e08e5d1bf0945a960fa1fafed56392c167ac5203693925b04ab67ada77b4b8969d697f0f17d2860e758ecda9a98d6a98d0405fcc1bc13ef360c8cdb6bbb821293d",
"acba95a4699263d14effffef5c454e18dd77d0c319e3177ee3052b95f5ad12953f312359959345720f9fa58aacc42f3087687b8fedf4a03a50b67ede7b2719049f008434fb6fc02d4ac80502f8d8f4ce6be3ae729412572a89bd8442118eb61517625cf6ec00b9ff5bed334c1af93dd32d208c662c4b98d45a25ed7bb5410ef0e9f3d1cf628d1458a1e67ab7af2b39eda08b709f917bec7fe63a4b4aaac5a662a921098f9fbc5f61c6208ca44ab36241bdff9b0dd5d621329b9ff262e4ce239c",
    ];

    for (node_idx, expected_eks) in EXPECTED_EKS_VALUE.iter().enumerate() {
        let node_sk = poly.evaluate_at(&Scalar::from_node_index(node_idx as u32));
        let eks = EncryptedKeyShare::create(&mut rng, &master_pk, &node_sk, &tpk, &context, &input);
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
    input: Vec<u8>,
    context: DerivationContext,
    derived_pk: DerivedPublicKey,
}

impl<'a> VetkdTestProtocolExecution<'a> {
    fn new<R: Rng + CryptoRng>(
        rng: &mut R,
        setup: &'a VetkdTestProtocolSetup,
    ) -> VetkdTestProtocolExecution<'a> {
        let input = rng.gen::<[u8; 32]>().to_vec();
        let context = random_derivation_context(rng);

        let derived_pk = DerivedPublicKey::compute_derived_key(&setup.master_pk, &context);

        Self {
            setup,
            input,
            context,
            derived_pk,
        }
    }

    fn create_encrypted_key_shares<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        input: Option<&[u8]>,
    ) -> Vec<(u32, G2Affine, EncryptedKeyShare)> {
        let mut node_info = Vec::with_capacity(self.setup.nodes);

        let input = input.unwrap_or(&self.input);

        for (node_idx, (node_pk, node_sk)) in self.setup.node_key_material.iter().enumerate() {
            let eks = EncryptedKeyShare::create(
                rng,
                &self.setup.master_pk,
                node_sk,
                &self.setup.transport_pk,
                &self.context,
                input,
            );

            assert!(eks.is_valid(
                &self.setup.master_pk,
                node_pk,
                &self.context,
                input,
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
            &self.context,
            &self.input,
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
            &self.context,
            &self.input,
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

    let nodes = 34;
    let threshold = 23;

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
                &proto.context,
                &proto.input,
                &setup.transport_pk
            ));

            let k = setup
                .transport_sk
                .decrypt(&ek, &proto.derived_pk, &proto.input)
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
    let msg = G1Affine::augmented_hash(proto.derived_pk.point(), &proto.input);

    assert!(verify_bls_signature(
        &vetkey,
        proto.derived_pk.point(),
        &msg
    ));

    // Check that if we introduce incorrect shares then combine_all will fail

    let other_input = rng.gen::<[u8; 24]>();
    assert_ne!(proto.input, other_input);
    let node_info_wrong_input = proto.create_encrypted_key_shares(rng, Some(&other_input));

    let node_eks_wrong_input = node_info_wrong_input
        .iter()
        .map(|(idx, _pk, eks)| (*idx, eks.clone()))
        .collect::<Vec<_>>();

    // With combine_all even if we provide sufficiently many valid shares
    // if any one share is invalid then combination will fail
    for rec_threshold in 2..nodes {
        let mut shares = random_subset(rng, &node_eks, rec_threshold - 1);

        // Avoid using a duplicate index for this test
        let random_unused_idx = loop {
            let idx = (rng.gen::<usize>() % node_eks_wrong_input.len()) as u32;
            if !shares.iter().map(|(i, _eks)| *i).any(|x| x == idx) {
                break idx as usize;
            }
        };

        shares.push(node_eks_wrong_input[random_unused_idx].clone());
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
        shares.append(&mut random_subset(rng, &node_info_wrong_input, 4));
        shares.shuffle(rng);

        let combined = proto.combine_valid(&shares);
        assert!(combined.is_ok(), "Combination unexpectedly failed");

        let k = setup
            .transport_sk
            .decrypt(
                &combined.expect("Already checked"),
                &proto.derived_pk,
                &proto.input,
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
