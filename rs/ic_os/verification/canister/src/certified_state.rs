use attestation_token::AttestationTokenPayload;
use candid::Principal;
use ic_certification::{AsHashTree, Hash, HashTree, NestedTree};
use std::cell::RefCell;

#[derive(Default)]
pub struct CertifiedState {
    state: RefCell<NestedTree<Vec<u8>, Vec<u8>>>,
}

impl CertifiedState {
    pub fn insert_attestation_token(
        &self,
        tls_public_key: Vec<u8>,
        attestation_token_payload: &AttestationTokenPayload,
    ) -> anyhow::Result<()> {
        self.state.borrow_mut().insert(
            &[
                attestation_token::ATTESTATION_TOKENS_LABEL.to_vec(),
                tls_public_key,
            ],
            serde_cbor::to_vec(attestation_token_payload)?,
        );
        Ok(())
    }

    pub fn attestation_token_witness(&self, public_tls_key: &[u8]) -> Option<HashTree> {
        let path = &[
            attestation_token::ATTESTATION_TOKENS_LABEL.to_vec(),
            public_tls_key.to_vec(),
        ];
        self.state
            .borrow()
            .contains_leaf(path)
            .then(|| self.state.borrow().witness(path))
    }

    pub(crate) fn digest(&self) -> Hash {
        self.state.borrow().root_hash()
    }
}
