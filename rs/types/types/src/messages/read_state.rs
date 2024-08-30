use crate::{
    messages::{
        http::representation_independent_hash_read_state, HttpReadState, HttpRequestError,
        MessageId,
    },
    PrincipalId, UserId,
};
use ic_crypto_tree_hash::Path;
use std::convert::TryFrom;

/// A `read_state` request sent from the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadState {
    pub source: UserId,
    pub paths: Vec<Path>,
    pub ingress_expiry: u64,
    pub nonce: Option<Vec<u8>>,
}

impl ReadState {
    pub fn id(&self) -> MessageId {
        MessageId::from(representation_independent_hash_read_state(
            self.ingress_expiry,
            self.paths.as_slice(),
            self.source.get().into_vec(),
            self.nonce.as_deref(),
        ))
    }
}

impl TryFrom<HttpReadState> for ReadState {
    type Error = HttpRequestError;

    fn try_from(read_state: HttpReadState) -> Result<Self, Self::Error> {
        Ok(Self {
            source: UserId::from(PrincipalId::try_from(read_state.sender.0).map_err(|err| {
                HttpRequestError::InvalidPrincipalId(format!(
                    "Converting sender to PrincipalId failed with {}",
                    err
                ))
            })?),
            paths: read_state.paths,
            ingress_expiry: read_state.ingress_expiry,
            nonce: read_state.nonce.map(|n| n.0),
        })
    }
}
