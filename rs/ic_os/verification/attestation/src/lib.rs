use rand::Rng;

pub mod attestation;
pub mod attestation_report;
pub mod certificates;
pub mod custom_data;
mod error;
pub mod protocol;
pub mod verify;

#[path = "gen/verification.attestation.rs"]
pub mod types;

pub fn generate_nonce() -> Vec<u8> {
    let mut rng = rand::rng();
    let mut nonce = vec![0u8; 32];
    rng.fill(&mut nonce[..]);
    nonce
}
