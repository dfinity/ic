use crate::proxy::{ProtoProxy, ProxyDecodeError};
use prost::Message;
use std::convert::TryFrom;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Height(u64);
#[derive(Debug, Clone, PartialEq, Eq)]
struct Blob(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Block {
    pub height: Height,
    pub payload: Blob,
}

mod pb {
    // Pretend Prost-generated message,
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Block {
        #[prost(uint64, tag = "1")]
        pub height: u64,
        #[prost(bytes, tag = "2")]
        pub payload: std::vec::Vec<u8>,
    }
}

impl From<Block> for pb::Block {
    fn from(value: Block) -> Self {
        Self {
            height: value.height.0,
            payload: value.payload.0,
        }
    }
}
impl TryFrom<pb::Block> for Block {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::Block) -> Result<Self, Self::Error> {
        if value.payload.is_empty() {
            return Err(ProxyDecodeError::MissingField("Block::payload"));
        }
        Ok(Self {
            height: Height(value.height),
            payload: Blob(value.payload),
        })
    }
}

#[test]
fn success() {
    let b = Block {
        height: Height(1),
        payload: Blob(vec![1, 2, 3]),
    };

    let bytes: Vec<u8> = pb::Block::proxy_encode(b.clone()).unwrap();
    assert_eq!(b, pb::Block::proxy_decode(&bytes).unwrap());
}

#[test]
fn missing_field() {
    let b = pb::Block {
        height: 1,
        payload: vec![],
    };

    let mut bytes = Vec::new();
    b.encode(&mut bytes).unwrap();
    match <pb::Block as ProtoProxy<Block>>::proxy_decode(&bytes) {
        Err(ProxyDecodeError::MissingField("Block::payload")) => {}
        other => panic!("Expected Err(MissingField), got {:?}", other),
    }
}
