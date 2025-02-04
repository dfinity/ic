use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use prost::Message;
use std::borrow::Cow;

include!(concat!(env!("OUT_DIR"), "/proto.rs"));

impl Storable for NonceInfo {
    fn to_bytes(&self) -> Cow<[u8]> {
        self.encode_to_vec().into()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).expect("Expected valid NonceInfo")
    }

    const BOUND: Bound = Bound::Unbounded;
}
