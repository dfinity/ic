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
        attestation_token_payload: &AttestationTokenPayload,
    ) -> anyhow::Result<()> {
        self.state.borrow_mut().insert(
            &[
                attestation_token::ATTESTATION_TOKENS_LABEL.to_vec(),
                attestation_token_payload.node_id.as_slice().to_vec(),
            ],
            serde_cbor::to_vec(attestation_token_payload)?,
        );
        Ok(())
    }

    pub fn attestation_token_witness(&self, node_id: &Principal) -> Option<HashTree> {
        let path = &[
            attestation_token::ATTESTATION_TOKENS_LABEL.to_vec(),
            node_id.as_slice().to_vec(),
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
