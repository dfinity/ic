use ic_types::crypto::{AlgorithmId, BasicSig, BasicSigOf, UserPublicKey, DOMAIN_IC_REQUEST};
use ic_types::messages::MessageId;
use rand::{CryptoRng, Rng};

pub fn ed25519_signature_and_public_key<R: Rng + CryptoRng>(
    request_id: &MessageId,
    rng: &mut R,
) -> (BasicSigOf<MessageId>, UserPublicKey) {
    let signing_key = ic_crypto_ed25519::PrivateKey::generate_using_rng(rng);
    let signature: BasicSigOf<MessageId> = {
        let bytes_to_sign = {
            let mut buf = vec![];
            buf.extend_from_slice(DOMAIN_IC_REQUEST);
            buf.extend_from_slice(request_id.as_bytes());
            buf
        };
        let signature_bytes = signing_key.sign_message(&bytes_to_sign);
        BasicSigOf::new(BasicSig(signature_bytes.to_vec()))
    };
    let public_key = UserPublicKey {
        key: signing_key.public_key().serialize_raw().to_vec(),
        algorithm_id: AlgorithmId::Ed25519,
    };
    (signature, public_key)
}
