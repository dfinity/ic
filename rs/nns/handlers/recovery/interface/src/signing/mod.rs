use super::Result;

pub mod ed25519;
pub mod p256;

pub trait Verifier: TryFrom<Vec<u8>> {
    fn verify_payload(&self, payload: &Vec<u8>, signature: &Vec<u8>) -> Result<()>;
}
pub trait Signer: TryInto<Vec<u8>> + Verifier {
    fn sign_payload(&self, payload: &Vec<u8>) -> Result<Vec<u8>>;
}
