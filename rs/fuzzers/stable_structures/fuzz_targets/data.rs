use arbitrary::Arbitrary;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

pub const MAX_VALUE_SIZE: u32 = 100;

#[derive(PartialEq, PartialOrd, Debug, Arbitrary, Deserialize, Serialize)]
pub struct BoundedFuzzStruct {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(PartialEq, PartialOrd, Debug, Arbitrary, Deserialize, Serialize)]
pub struct UnboundedFuzzStruct {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

// The struct has size bounds reflected by Bound::Bounded::max_size
impl Storable for BoundedFuzzStruct {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(serde_cbor::ser::to_vec(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        let value: Self = serde_cbor::de::from_slice(bytes.as_ref()).unwrap();
        value
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: MAX_VALUE_SIZE * 2,
        is_fixed_size: false,
    };
}

// The struct has no size bounds
impl Storable for UnboundedFuzzStruct {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(serde_cbor::ser::to_vec(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        let value: Self = serde_cbor::de::from_slice(bytes.as_ref()).unwrap();
        value
    }

    const BOUND: Bound = Bound::Unbounded;
}
