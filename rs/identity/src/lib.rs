use ic_crypto_ed25519::{PrivateKey, PrivateKeyFormat};

/// Generates the key and returns the (secret, public) pair encoded as PEM and
/// DER, respectivelys.
pub fn generate_key() -> (String, Vec<u8>) {
    let signing_key = PrivateKey::generate();

    let secret_pem = signing_key.serialize_pkcs8_pem(PrivateKeyFormat::Pkcs8v2WithRingBug);
    let public_der = signing_key.public_key().serialize_rfc8410_der();

    (secret_pem, public_der)
}
