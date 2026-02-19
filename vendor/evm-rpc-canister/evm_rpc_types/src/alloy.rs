use crate::{Hex, Hex20, Hex256, Hex32, Nat256, RpcError};
use alloy_primitives::ruint::{ToUintError, UintTryFrom};

impl From<Hex20> for alloy_primitives::Address {
    fn from(value: Hex20) -> Self {
        Self::from(<[u8; 20]>::from(value))
    }
}

impl From<alloy_primitives::Address> for Hex20 {
    fn from(value: alloy_primitives::Address) -> Self {
        Self::from(value.into_array())
    }
}

impl From<Hex32> for alloy_primitives::B256 {
    fn from(value: Hex32) -> Self {
        Self::from(<[u8; 32]>::from(value))
    }
}

impl From<alloy_primitives::B256> for Hex32 {
    fn from(value: alloy_primitives::B256) -> Self {
        Self::from(value.0)
    }
}

impl<const N: usize> From<alloy_primitives::FixedBytes<N>> for Hex {
    fn from(value: alloy_primitives::FixedBytes<N>) -> Self {
        Self::from(value.to_vec())
    }
}

impl From<Hex> for alloy_primitives::Bytes {
    fn from(value: Hex) -> Self {
        Self::from_iter(Vec::<u8>::from(value))
    }
}

impl From<alloy_primitives::Bytes> for Hex {
    fn from(value: alloy_primitives::Bytes) -> Self {
        Hex(value.to_vec())
    }
}

impl From<alloy_primitives::U256> for Nat256 {
    fn from(value: alloy_primitives::U256) -> Self {
        Nat256::from_be_bytes(value.to_be_bytes())
    }
}

impl UintTryFrom<Nat256> for alloy_primitives::U256 {
    fn uint_try_from(value: Nat256) -> Result<Self, ToUintError<Self>> {
        Ok(alloy_primitives::U256::from_be_bytes(value.into_be_bytes()))
    }
}

impl From<Hex256> for alloy_primitives::Bloom {
    fn from(value: Hex256) -> Self {
        alloy_primitives::Bloom::from(value.0)
    }
}

impl From<alloy_primitives::Bloom> for Hex256 {
    fn from(value: alloy_primitives::Bloom) -> Self {
        Hex256::from(value.into_array())
    }
}

impl TryFrom<Nat256> for alloy_primitives::B64 {
    type Error = RpcError;

    fn try_from(value: Nat256) -> Result<Self, Self::Error> {
        Ok(alloy_primitives::B64::from(u64::try_from(value)?))
    }
}

impl From<alloy_primitives::B64> for Nat256 {
    fn from(value: alloy_primitives::B64) -> Self {
        Nat256::from(u64::from(value))
    }
}
