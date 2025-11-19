use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, Scalar};
use ic_crypto_internal_bls12_381_vetkd::{
    DerivationContext, EncryptedKey, EncryptedKeyShare, TransportPublicKey,
};
use rand_chacha::rand_core::SeedableRng;

pub fn dummy_transport_public_key() -> [u8; 48] {
    G1Affine::generator().serialize()
}

pub struct PrivateKey {
    secret_key: Scalar,
    public_point: G2Affine,
    pk_bytes: Vec<u8>,
}

impl PrivateKey {
    pub fn generate(seed: &[u8]) -> Self {
        let secret_key = Scalar::hash(b"ic-crypto-vetkd-test-utils-generate-test-key", seed);
        Self::from_scalar(secret_key)
    }

    fn from_scalar(secret_key: Scalar) -> Self {
        let public_point = G2Affine::from(G2Affine::generator() * &secret_key);
        let pk_bytes = public_point.serialize().to_vec();
        Self {
            secret_key,
            public_point,
            pk_bytes,
        }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.pk_bytes.clone()
    }

    pub fn vetkd_protocol(
        &self,
        canister_id: &[u8],
        context: &[u8],
        input: &[u8],
        tpk: &[u8],
        seed: &[u8; 32],
    ) -> Vec<u8> {
        let dc = DerivationContext::new(canister_id, context);

        let tpk =
            TransportPublicKey::deserialize(tpk).expect("Failed to deserialize TransportPublicKey");

        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);

        let eks = EncryptedKeyShare::create(
            &mut rng,
            &self.public_point,
            &self.secret_key,
            &tpk,
            &dc,
            input,
        );

        let mut shares = std::collections::BTreeMap::new();
        shares.insert(0, eks);

        let ek = EncryptedKey::combine_all(&shares, 1, &self.public_point, &tpk, &dc, input)
            .expect("Failed to combine single EncryptedKeyShare to an EncryptedKey");

        ek.serialize().to_vec()
    }
}
