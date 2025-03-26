use rand::Rng;

pub mod attestation;
pub mod custom_data;
mod error;
pub mod protocol;
pub mod types;
pub mod verify;

pub fn generate_nonce() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut nonce = vec![0u8; 32];
    rng.fill(&mut nonce[..]);
    nonce
}
