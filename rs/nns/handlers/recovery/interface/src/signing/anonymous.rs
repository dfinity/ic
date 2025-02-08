use super::{Signer, Verifier};

pub struct AnonymousSigner;

impl Verifier for AnonymousSigner {
    fn verify_payload(&self, _: &[u8], _: &[u8]) -> crate::Result<()> {
        Ok(())
    }

    fn to_public_key_der(&self) -> crate::Result<Vec<u8>> {
        Ok(vec![])
    }
}

impl Signer for AnonymousSigner {
    fn sign_payload(&self, _: &[u8]) -> crate::Result<Vec<u8>> {
        Ok(vec![])
    }
}
