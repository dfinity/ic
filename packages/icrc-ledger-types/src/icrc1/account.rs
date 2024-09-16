use std::{
    error::Error,
    fmt::{self, Display},
    str::FromStr,
};

use base32::Alphabet;
use candid::{types::principal::PrincipalError, CandidType, Deserialize, Principal};
use ic_stable_structures::{storable::Bound, Storable};
use serde::Serialize;
use std::borrow::Cow;
use std::io::{Cursor, Read};

pub type Subaccount = [u8; 32];

pub const DEFAULT_SUBACCOUNT: &Subaccount = &[0; 32];

// Account representation of ledgers supporting the ICRC1 standard
#[derive(Serialize, CandidType, Deserialize, Clone, Debug, Copy)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Subaccount>,
}

impl Account {
    #[inline]
    pub fn effective_subaccount(&self) -> &Subaccount {
        self.subaccount.as_ref().unwrap_or(DEFAULT_SUBACCOUNT)
    }
}

impl PartialEq for Account {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner && self.effective_subaccount() == other.effective_subaccount()
    }
}

impl Eq for Account {}

impl std::cmp::PartialOrd for Account {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Account {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.owner.cmp(&other.owner).then_with(|| {
            self.effective_subaccount()
                .cmp(other.effective_subaccount())
        })
    }
}

impl std::hash::Hash for Account {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.owner.hash(state);
        self.effective_subaccount().hash(state);
    }
}

fn full_account_checksum(owner: &[u8], subaccount: &[u8]) -> String {
    let mut crc32hasher = crc32fast::Hasher::new();
    crc32hasher.update(owner);
    crc32hasher.update(subaccount);
    let checksum = crc32hasher.finalize().to_be_bytes();
    base32::encode(Alphabet::RFC4648 { padding: false }, &checksum).to_lowercase()
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/TextualEncoding.md#textual-encoding-of-icrc-1-accounts
        match &self.subaccount {
            None => write!(f, "{}", self.owner),
            Some(subaccount) if subaccount == &[0; 32] => write!(f, "{}", self.owner),
            Some(subaccount) => {
                let checksum = full_account_checksum(self.owner.as_slice(), subaccount.as_slice());
                let hex_subaccount = hex::encode(subaccount.as_slice());
                let hex_subaccount = hex_subaccount.trim_start_matches('0');
                write!(f, "{}-{}.{}", self.owner, checksum, hex_subaccount)
            }
        }
    }
}

impl From<Principal> for Account {
    fn from(owner: Principal) -> Self {
        Self {
            owner,
            subaccount: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ICRC1TextReprError {
    DefaultSubaccountShouldBeOmitted,
    InvalidChecksum { expected: String },
    InvalidPrincipal(PrincipalError),
    InvalidSubaccount(String),
    LeadingZeroesInSubaccount,
    MissingChecksum,
}

impl Display for ICRC1TextReprError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ICRC1TextReprError::DefaultSubaccountShouldBeOmitted => {
                write!(f, "default subaccount should be omitted")
            }
            ICRC1TextReprError::InvalidChecksum { expected } => {
                write!(f, "invalid checksum (expected: {})", expected)
            }
            ICRC1TextReprError::InvalidPrincipal(e) => write!(f, "invalid principal: {}", e),
            ICRC1TextReprError::InvalidSubaccount(e) => write!(f, "invalid subaccount: {}", e),
            ICRC1TextReprError::LeadingZeroesInSubaccount => {
                write!(f, "subaccount should not have leading zeroes")
            }
            ICRC1TextReprError::MissingChecksum => write!(f, "missing checksum"),
        }
    }
}

impl Error for ICRC1TextReprError {}

impl FromStr for Account {
    type Err = ICRC1TextReprError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('.') {
            Some((principal_checksum, subaccount)) => {
                let (principal, checksum) = match principal_checksum.rsplit_once('-') {
                    // The checksum is 7 characters (crc32 encoded via base32) while principal
                    // groups are 5 characters
                    Some((_, checksum)) if checksum.len() != 7 => {
                        return Err(Self::Err::MissingChecksum)
                    }
                    Some(principal_and_checksum) => principal_and_checksum,
                    None => return Err(Self::Err::MissingChecksum),
                };
                if subaccount.starts_with('0') {
                    return Err(Self::Err::LeadingZeroesInSubaccount);
                }
                let owner = Principal::from_str(principal).map_err(Self::Err::InvalidPrincipal)?;
                let subaccount = hex::decode(format!("{:0>64}", subaccount)).map_err(|e| {
                    Self::Err::InvalidSubaccount(format!("subaccount is not hex-encoded: {e}"))
                })?;
                let subaccount: Subaccount = subaccount.try_into().map_err(|_| {
                    Self::Err::InvalidSubaccount("subaccount is longer than 32 bytes".to_string())
                })?;
                if &subaccount == DEFAULT_SUBACCOUNT {
                    return Err(Self::Err::DefaultSubaccountShouldBeOmitted);
                }
                let expected_checksum =
                    full_account_checksum(owner.as_slice(), subaccount.as_slice());
                if checksum != expected_checksum {
                    return Err(Self::Err::InvalidChecksum {
                        expected: expected_checksum,
                    });
                }
                Ok(Self {
                    owner,
                    subaccount: Some(subaccount),
                })
            }
            None => Principal::from_str(s)
                .map_err(Self::Err::InvalidPrincipal)
                .map(Account::from),
        }
    }
}

impl Storable for Account {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buffer: Vec<u8> = vec![];
        let mut buffer0: Vec<u8> = vec![];

        if let Some(subaccount) = self.subaccount {
            buffer0.extend(subaccount.as_slice());
        }
        buffer0.extend(self.owner.as_slice());
        buffer.extend((buffer0.len() as u8).to_le_bytes());
        buffer.append(&mut buffer0);

        Cow::Owned(buffer)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut cursor = Cursor::new(bytes);

        let mut len_bytes = [0u8; 1];
        cursor
            .read_exact(&mut len_bytes)
            .expect("Unable to read the len of the account");
        let mut len = u8::from_le_bytes(len_bytes);
        let subaccount = if len >= 32 {
            let mut subaccount_bytes = [0u8; 32];
            cursor
                .read_exact(&mut subaccount_bytes)
                .expect("Unable to read the bytes of the account's subaccount");
            len -= 32;
            Some(subaccount_bytes)
        } else {
            None
        };
        let mut owner_bytes = vec![0; len as usize];
        cursor
            .read_exact(&mut owner_bytes)
            .expect("Unable to read the bytes of the account's owners");
        let owner = Principal::from_slice(&owner_bytes);
        Account { owner, subaccount }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 62,
        is_fixed_size: false,
    };
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use std::str::FromStr;

    use candid::Principal;

    use crate::icrc1::account::{Account, ICRC1TextReprError};

    #[test]
    fn test_account_display_default_subaccount() {
        let owner = Principal::anonymous();
        let account = Account::from(owner);
        assert_eq!(account.to_string(), owner.to_string());
    }

    #[test]
    fn test_account_display_trim_subaccount() {
        let owner =
            Principal::from_text("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
                .unwrap();
        let subaccount = Some(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let account = Account { owner, subaccount };
        assert_eq!(
            account.to_string(),
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i.1"
        );
    }

    #[test]
    fn test_account_display_full_subaccount() {
        let owner =
            Principal::from_text("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
                .unwrap();
        let subaccount = Some(
            hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let account = Account { owner, subaccount };
        assert_eq!(account.to_string(), "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-dfxgiyy.102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    }

    #[test]
    fn test_account_from_str_principal_only() {
        let str = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae";
        assert_eq!(
            Account::from_str(str),
            Ok(Account::from(Principal::from_str(str).unwrap()))
        );
    }

    #[test]
    fn test_account_from_str_err_def_subaccout_should_be_omitted() {
        let str = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-q6bn32y.";
        assert_eq!(
            Account::from_str(str),
            Err(ICRC1TextReprError::DefaultSubaccountShouldBeOmitted)
        );
    }

    #[test]
    fn test_account_from_str_err_invalid_principal() {
        let str = "k2t6j2nvnp4zjm3-25dtz6xhaac7boj5gayfoj3xs-i43lp-teztq-6ae";
        assert_matches!(
            Account::from_str(str),
            Err(ICRC1TextReprError::InvalidPrincipal(_))
        );
    }

    #[test]
    fn test_account_from_str_subaccount_1() {
        let str = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i.1";
        let owner =
            Principal::from_str("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
                .unwrap();
        let subaccount = Some(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(Account::from_str(str), Ok(Account { owner, subaccount }));
    }

    #[test]
    fn test_account_from_str_err_subaccount_leading_zeroes() {
        let str = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i.01";
        assert_eq!(
            Account::from_str(str),
            Err(ICRC1TextReprError::LeadingZeroesInSubaccount)
        );
    }

    #[test]
    fn test_account_from_err_missing_checksum() {
        let str = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae.1";
        assert_eq!(
            Account::from_str(str),
            Err(ICRC1TextReprError::MissingChecksum)
        );
    }

    #[test]
    fn test_account_from_str_full_subaccount() {
        let str = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-dfxgiyy.102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let owner =
            Principal::from_str("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
                .unwrap();
        let subaccount = Some(
            hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(Account::from_str(str), Ok(Account { owner, subaccount }));
    }

    #[test]
    fn test_account_from_str_invalid_subaccount() {
        let str = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-aaaaaaa.102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000";
        assert_matches!(
            Account::from_str(str),
            Err(ICRC1TextReprError::InvalidSubaccount(_))
        );
    }

    #[test]
    fn test_account_from_str_invalid_checksum() {
        let str = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-aaaaaaa.1";
        assert_matches!(
            Account::from_str(str),
            Err(ICRC1TextReprError::InvalidChecksum { expected: _ })
        );
    }
}
