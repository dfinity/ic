use super::{account::Account, base32::base32_decode};
use candid::{CandidType, Deserialize, Principal};
use serde::Serialize;

use std::{cmp, fmt, hash, mem::size_of};

#[derive(CandidType, Deserialize, Serialize, Clone, Copy, Debug, PartialEq)]
pub struct Subaccount(pub [u8; 32]);

pub const DEFAULT_SUBACCOUNT: Subaccount = Subaccount([0u8; 32]);

impl Default for Subaccount {
    fn default() -> Self {
        Subaccount([0u8; 32])
    }
}

impl Subaccount {
    pub fn new(nonce: u64) -> Self {
        let mut subaccount = [0; 32];
        // Convert the nonce into bytes in big-endian order
        let nonce_bytes = nonce.to_be_bytes();
        // Copy the nonce bytes into the subaccount array starting from the 25th byte
        // as the nonce in big-endian order with doing this we get the smallest ICRCAccount ids
        subaccount[24..].copy_from_slice(&nonce_bytes);

        Subaccount(subaccount)
    }

    pub fn nonce(&self) -> u64 {
        if self.0[0] == 29 {
            return 0;
        }

        let nonce_bytes = &self.0[24..];
        u64::from_be_bytes(nonce_bytes.try_into().unwrap())
    }

    pub fn is_default(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, SubaccountError> {
        if slice.len() != 32 {
            return Err(SubaccountError::SliceError(
                "Slice must be 32 bytes long".to_string(),
            ));
        }

        let mut subaccount = [0; 32];
        subaccount.copy_from_slice(slice);

        Ok(Subaccount(subaccount))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn from_hex(hex: &str) -> Result<Self, SubaccountError> {
        // add leading zeros if necessary
        let hex = if hex.len() < 64 {
            let mut hex = hex.to_string();
            hex.insert_str(0, &"0".repeat(64 - hex.len()));
            hex
        } else {
            hex.to_string()
        };

        let bytes = hex::decode(hex).map_err(|e| SubaccountError::HexError(e.to_string()))?;

        Subaccount::from_slice(&bytes)
    }

    pub fn from_base32(base32: &str) -> Result<Self, SubaccountError> {
        let bytes =
            base32_decode(base32).map_err(|e| SubaccountError::Base32Error(e.to_string()))?;
        Subaccount::from_slice(&bytes)
    }
}

impl Subaccount {
    pub fn account(&self, owner: Principal) -> Account {
        Account::new(owner, Some(self.clone()))
    }
}

impl Eq for Subaccount {}

impl cmp::PartialOrd for Subaccount {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for Subaccount {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl hash::Hash for Subaccount {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl From<Principal> for Subaccount {
    fn from(principal: Principal) -> Self {
        let mut subaccount = [0; size_of::<Subaccount>()];
        let principal_id = principal.as_slice();

        subaccount[0] = principal_id.len().try_into().unwrap();
        subaccount[1..1 + principal_id.len()].copy_from_slice(principal_id);

        Subaccount(subaccount)
    }
}

impl From<[u8; 32]> for Subaccount {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<Vec<u8>> for Subaccount {
    type Error = SubaccountError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(SubaccountError::InvalidSubaccountLength(value.len()));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&value);

        Ok(Self(bytes))
    }
}

impl TryFrom<&str> for Subaccount {
    type Error = SubaccountError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes =
            hex::decode(value).map_err(|e| SubaccountError::InvalidSubaccount(e.to_string()))?;

        Ok(Self::try_from(bytes)?)
    }
}

impl fmt::Display for Subaccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(&self.0).fmt(f)
    }
}

#[derive(CandidType, Deserialize, Serialize, Debug)]
pub enum SubaccountError {
    HexError(String),
    SliceError(String),
    Base32Error(String),
    InvalidSubaccount(String),
    InvalidSubaccountLength(usize),
}

#[rustfmt::skip]
impl fmt::Display for SubaccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubaccountError::InvalidSubaccountLength(len) => write!(f, "InvalidSubaccountLength: {}", len),
            SubaccountError::InvalidSubaccount(e) => write!(f, "InvalidSubaccount: {}", e),
            SubaccountError::Base32Error(e) => write!(f, "Subaccount base32 error: {}", e),
            SubaccountError::SliceError(e) => write!(f, "Subaccount slice error: {}", e),
            SubaccountError::HexError(e) => write!(f, "Subaccount hex error: {}", e),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_subaccount() {
        let subaccount = Subaccount::default();
        assert_eq!(
            subaccount.to_owned(),
            Subaccount([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ])
        );

        let subaccount = Subaccount::new(0);
        assert_eq!(
            subaccount.to_owned(),
            Subaccount([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ])
        );

        let subaccount = Subaccount::new(1);

        assert_eq!(subaccount.nonce(), 1);

        assert_eq!(
            subaccount.to_owned(),
            Subaccount([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ])
        );

        assert_eq!(
            subaccount.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );

        let subaccount = Subaccount::try_from(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("Failed to parse subaccount");

        assert_eq!(
            subaccount,
            Subaccount([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ])
        );

        let subaccount = Subaccount::new(512);

        assert_eq!(
            subaccount.to_owned(),
            Subaccount([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0
            ])
        )
    }

    #[test]
    fn test_account_and_subaccount_with_loop() {
        let principal = Principal::management_canister();

        for i in 0..30 {
            let nonce = i / 3;

            let subaccount = Subaccount::new(nonce);
            let account = Account::new(principal, Some(subaccount.clone()));

            assert_eq!(account.effective_subaccount(), &subaccount);

            let recover = Account::from_text(&account.to_text()).unwrap();

            assert_eq!(recover.effective_subaccount().nonce(), nonce);

            assert_eq!(recover, account);
        }
    }
}
