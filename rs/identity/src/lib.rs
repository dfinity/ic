use ic_crypto_internal_types::sign::eddsa::ed25519::{PublicKey, SecretKey};
use ic_crypto_utils_basic_sig::conversions::{Ed25519Conversions, Ed25519SecretKeyConversions};
use rand::rngs::OsRng;
use std::convert::TryInto;

// sadly, we have to repeat the implementation
fn secret_to_array(v: Vec<u8>) -> [u8; SecretKey::SIZE] {
    let len = v.len();
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[u8; SecretKey::SIZE]> = boxed_slice.try_into().unwrap_or_else(|_| {
        panic!(
            "Expected a secret key of length {} but it was {}",
            SecretKey::SIZE,
            len
        )
    });
    *boxed_array
}

fn public_to_array(v: Vec<u8>) -> [u8; PublicKey::SIZE] {
    let len = v.len();
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[u8; PublicKey::SIZE]> = boxed_slice.try_into().unwrap_or_else(|_| {
        panic!(
            "Expected a public key of length {} but it was {}",
            SecretKey::SIZE,
            len
        )
    });
    *boxed_array
}

/// Generates the key and returns the (secret, public) pair encoded as PEM and
/// DER, respectively.
pub fn generate_key() -> (String, Vec<u8>) {
    let mut csprng = OsRng {};
    let keypair = ed25519_dalek::Keypair::generate(&mut csprng);

    let secret_key: SecretKey = {
        let sk = keypair.secret.to_bytes().to_vec();
        SecretKey(secret_to_array(sk))
    };
    let public_key: PublicKey = {
        let pk = keypair.public.to_bytes().to_vec();
        PublicKey(public_to_array(pk))
    };

    let secret_pem = secret_key.to_pem(&public_key);
    let public_der = public_key.to_der();

    (secret_pem, public_der)
}
