use crate::{
    messages::{
        message_id::hash_of_map, HttpHandlerError, HttpReadState, MessageId, RawHttpRequestVal,
    },
    PrincipalId, UserId,
};
use ic_crypto_tree_hash::Path;
use maplit::btreemap;
use std::convert::TryFrom;

/// A `read_state` request sent from the user.
#[derive(Clone, Debug, PartialEq)]
pub struct ReadState {
    pub source: UserId,
    pub paths: Vec<Path>,
    pub ingress_expiry: u64,
    pub nonce: Option<Vec<u8>>,
}

impl ReadState {
    // TODO(EXC-237): Avoid the duplication between this method and the one in
    // `HttpReadState`.
    pub fn id(&self) -> MessageId {
        use RawHttpRequestVal::*;
        let mut map = btreemap! {
            "request_type".to_string() => String("read_state".to_string()),
            "ingress_expiry".to_string() => U64(self.ingress_expiry),
            "paths".to_string() => Array(self
                    .paths
                    .iter()
                    .map(|p| {
                        RawHttpRequestVal::Array(
                            p.iter()
                                .map(|b| RawHttpRequestVal::Bytes(b.clone().to_vec()))
                                .collect(),
                        )
                    })
                    .collect()),
            "sender".to_string() => Bytes(self.source.get().to_vec()),
        };
        if let Some(nonce) = &self.nonce {
            map.insert("nonce".to_string(), Bytes(nonce.clone()));
        }
        MessageId::from(hash_of_map(&map))
    }
}

impl TryFrom<HttpReadState> for ReadState {
    type Error = HttpHandlerError;

    fn try_from(read_state: HttpReadState) -> Result<Self, Self::Error> {
        Ok(Self {
            source: UserId::from(PrincipalId::try_from(read_state.sender.0).map_err(|err| {
                HttpHandlerError::InvalidPrincipalId(format!(
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
