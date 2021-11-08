use ic_types::crypto::{AlgorithmId, UserPublicKey};
use lazy_static::lazy_static;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use ic_crypto_internal_types::sign::eddsa::ed25519::{PublicKey, SecretKey};
use ic_crypto_utils_basic_sig::conversions::Ed25519SecretKeyConversions;

use ed25519_dalek::PublicKey as OtherPublicKey;
use ed25519_dalek::SecretKey as OtherSecretKey;

// get public key from the dedicated whitelisted private key used by the
// workload generator
fn get_pub() -> PublicKey {
    let contents = "-----BEGIN PRIVATE KEY-----\nMFMCAQEwBQYDK2VwBCIEILhMGpmYuJ0JEhDwocj6pxxOmIpGAXZd40AjkNhuae6q\noSMDIQBeXC6ae2dkJ8QC50bBjlyLqsFQFsMsIThWB21H6t6JRA==\n-----END PRIVATE KEY-----";
    let (_secret_key, public_key) = SecretKey::from_pem(contents).expect("Invalid secret key.");
    public_key
}

fn get_pair() -> ed25519_dalek::Keypair {
    let contents = "-----BEGIN PRIVATE KEY-----\nMFMCAQEwBQYDK2VwBCIEILhMGpmYuJ0JEhDwocj6pxxOmIpGAXZd40AjkNhuae6q\noSMDIQBeXC6ae2dkJ8QC50bBjlyLqsFQFsMsIThWB21H6t6JRA==\n-----END PRIVATE KEY-----";
    let (secret_key, public_key) = SecretKey::from_pem(contents).expect("Invalid secret key.");
    let secret_bytes = secret_key.as_bytes();
    let public_bytes = public_key.as_bytes();

    ed25519_dalek::Keypair {
        public: OtherPublicKey::from_bytes(public_bytes).unwrap(),
        secret: OtherSecretKey::from_bytes(secret_bytes).unwrap(),
    }
}

lazy_static! {
    // A keypair meant to be used in various test setups, including
    // but (not limited) to scenario tests, end-to-end tests and the
    // workload generator.
    pub static ref TEST_IDENTITY_KEYPAIR: ed25519_dalek::Keypair = {
        let mut rng = ChaChaRng::seed_from_u64(1_u64);
        ed25519_dalek::Keypair::generate(&mut rng)
    };

    // a dedicated identity for when we use --principal-id in the
    // workload generator
    pub static ref TEST_IDENTITY_KEYPAIR_HARD_CODED: ed25519_dalek::Keypair = {
        get_pair()
    };

    pub static ref PUBKEY : UserPublicKey = UserPublicKey {
        key: TEST_IDENTITY_KEYPAIR.public.to_bytes().to_vec(),
        algorithm_id: AlgorithmId::Ed25519,
    };

    pub static ref PUBKEY_PID : UserPublicKey = UserPublicKey {
        key: get_pub().as_bytes().to_vec(),
        algorithm_id: AlgorithmId::Ed25519,
    };

}
