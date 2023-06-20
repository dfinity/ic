use super::{
    base32::base32_encode,
    subaccount::{Subaccount, DEFAULT_SUBACCOUNT},
};
use candid::{CandidType, Deserialize, Principal};
use easy_hasher::easy_hasher;
use serde::Serialize;
use std::{cmp, fmt, hash, str::FromStr};

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Subaccount>,
}

impl Account {
    pub fn new(owner: Principal, subaccount: Option<Subaccount>) -> Self {
        Account { owner, subaccount }
    }

    pub fn from_text(text: &str) -> Result<Self, AccountError> {
        Self::from_str(text)
    }

    #[inline]
    pub fn effective_subaccount(&self) -> &Subaccount {
        self.subaccount.as_ref().unwrap_or(&DEFAULT_SUBACCOUNT)
    }

    fn compute_checksum(&self) -> Vec<u8> {
        // Create a buffer to hold the principal bytes and the subaccount bytes
        let mut buffer = Vec::with_capacity(29 + 32);

        // Add the owner principal bytes
        buffer.extend_from_slice(&self.owner.as_slice());

        // If subaccount exists, add the subaccount bytes. Otherwise add 32 zeros
        match &self.subaccount {
            Some(subaccount) => buffer.extend_from_slice(&subaccount.to_vec()),
            None => buffer.extend_from_slice(&[0u8; 32]),
        }

        // Compute the CRC32 checksum
        easy_hasher::raw_crc32(buffer).to_vec()
    }

    fn compute_base32_checksum(&self) -> String {
        base32_encode(&self.compute_checksum())
    }

    pub fn to_text(&self) -> String {
        self.to_string()
    }

    /// Returns the subaccount.clone()
    pub fn subaccount(&self) -> Option<Subaccount> {
        self.subaccount.clone()
    }

    /// Returns the owner.clone()
    pub fn owner(&self) -> Principal {
        self.owner.clone()
    }
}

impl PartialEq for Account {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner && self.effective_subaccount() == other.effective_subaccount()
    }
}

impl Eq for Account {}

impl cmp::PartialOrd for Account {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for Account {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.owner.cmp(&other.owner).then_with(|| {
            self.effective_subaccount()
                .cmp(other.effective_subaccount())
        })
    }
}

impl hash::Hash for Account {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.owner.hash(state);
        self.effective_subaccount().hash(state);
    }
}

impl From<Principal> for Account {
    fn from(principal: Principal) -> Self {
        Account {
            owner: principal,
            subaccount: None,
        }
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.subaccount {
            None => write!(f, "{}", self.owner),
            Some(subaccount) => {
                if subaccount.is_default() {
                    write!(f, "{}", self.owner)
                } else {
                    let checksum = self.compute_base32_checksum();
                    let hex_str = hex::encode(&subaccount.as_slice())
                        .trim_start_matches('0')
                        .to_owned();
                    write!(f, "{}-{}.{}", self.owner, checksum, hex_str)
                }
            }
        }
    }
}

impl FromStr for Account {
    type Err = AccountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n = s.len();

        if n == 0 {
            return Err(AccountError::Malformed("empty".into()));
        }

        let last_dash = s.rfind('-');
        let dot = s.find('.');

        match last_dash {
            None => {
                return Err(AccountError::Malformed(
                    "expected at least one dash ('-') character".into(),
                ));
            }
            Some(last_dash) => {
                if let Some(dot) = dot {
                    // There is a subaccount
                    let num_subaccount_digits = n - dot - 1;

                    if num_subaccount_digits > 64 {
                        return Err(AccountError::Malformed(
                            "the subaccount is too long (expected at most 64 characters)".into(),
                        ));
                    };

                    if dot < last_dash {
                        return Err(AccountError::Malformed(
                            "the subaccount separator does not follow the checksum separator"
                                .into(),
                        ));
                    };

                    if dot - last_dash - 1 != 7 {
                        return Err(AccountError::BadChecksum);
                    };

                    // The encoding ends with a dot, the subaccount is empty.
                    if dot == n - 1 {
                        return Err(AccountError::NotCanonical);
                    };

                    // The first digit after the dot must not be a zero.
                    if s.chars().nth(dot + 1).unwrap() == '0' {
                        return Err(AccountError::NotCanonical);
                    };

                    let principal_text = &s[..last_dash];
                    let owner = Principal::from_text(principal_text)
                        .map_err(|e| AccountError::InvalidPrincipal(e.to_string()))?;

                    let hex_str = &s[dot + 1..];

                    // Check that the subaccount is not the default.
                    if hex_str.chars().all(|c| c == '0') {
                        return Err(AccountError::NotCanonical);
                    };

                    let subaccount = Subaccount::from_hex(&hex_str)
                        .map_err(|e| AccountError::InvalidSubaccount(e.to_string()))?;

                    // Check that the checksum matches the subaccount.
                    let checksum = &s[last_dash + 1..dot];
                    let expected_checksum = base32_encode(
                        &Account {
                            owner,
                            subaccount: Some(subaccount.clone()),
                        }
                        .compute_checksum(),
                    );

                    if checksum != expected_checksum {
                        return Err(AccountError::BadChecksum);
                    };

                    Ok(Account {
                        owner,
                        subaccount: Some(subaccount),
                    })
                } else {
                    // There is no subaccount, so it's just a Principal
                    let owner = Principal::from_text(s)
                        .map_err(|e| AccountError::InvalidPrincipal(e.to_string()))?;
                    Ok(Account {
                        owner,
                        subaccount: None,
                    })
                }
            }
        }
    }
}

#[derive(CandidType, Clone, Deserialize, Debug, PartialEq)]
pub enum AccountError {
    InvalidFormat,
    BadChecksum,
    NotCanonical,
    HexDecode(String),
    Malformed(String),
    InvalidPrincipal(String),
    InvalidSubaccount(String),
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountError::BadChecksum => write!(f, "Bad checksum"),
            AccountError::NotCanonical => write!(f, "Not canonical"),
            AccountError::HexDecode(e) => write!(f, "Hex decode error: {}", e),
            AccountError::Malformed(e) => write!(f, "Malformed account: {}", e),
            AccountError::InvalidFormat => write!(f, "Invalid account format"),
            AccountError::InvalidPrincipal(e) => write!(f, "Invalid principal: {}", e),
            AccountError::InvalidSubaccount(e) => write!(f, "Invalid subaccount: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_display() {
        let account_1 = Account {
            owner: Principal::from_text(
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
            )
            .unwrap(),
            subaccount: None,
        };
        assert_eq!(
            account_1.to_string(),
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
        );

        let account_2 = Account {
            owner: Principal::from_text(
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
            )
            .unwrap(),
            subaccount: Some(Subaccount::from_slice(&[0u8; 32]).unwrap()),
        };
        assert_eq!(
            account_2.to_string(),
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
        );

        let account_3 = Account {
            owner: Principal::from_text(
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
            )
            .unwrap(),
            subaccount: Some(Subaccount::from_slice(&[1u8; 32]).unwrap()),
        };
        assert_eq!(
            account_3.to_string(),
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-7s4rpcq.101010101010101010101010101010101010101010101010101010101010101"
        );

        let mut slices = [0u8; 32];
        slices[31] = 0x01;

        let account_4 = Account {
            owner: Principal::from_text(
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
            )
            .unwrap(),
            subaccount: Some(Subaccount::from_slice(&slices).unwrap()),
        };

        assert_eq!(
            account_4.to_string(),
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i.1"
        );

        let slices = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let account_5 = Account {
            owner: Principal::from_text(
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
            )
            .unwrap(),
            subaccount: Some(Subaccount::from_slice(&slices).unwrap()),
        };
        assert_eq!(
            account_5.to_string(),
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-dfxgiyy.102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
    }

    #[test]
    fn test_account_parsing() {
        let account_1 =
            Account::from_text("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
                .unwrap();

        let expected_1 = Account {
            owner: Principal::from_text(
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
            )
            .unwrap(),
            subaccount: None,
        };

        assert_eq!(account_1, expected_1);

        let account_2 = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
            .parse::<Account>()
            .unwrap();

        let expected_2 = Account {
            owner: Principal::from_text(
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
            )
            .unwrap(),
            subaccount: Some(Subaccount([0u8; 32])),
        };

        assert_eq!(account_2, expected_2);

        let account_3 = Account::from_text(
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-7s4rpcq.101010101010101010101010101010101010101010101010101010101010101"
        ).unwrap();

        let expected_3 = Account {
            owner: Principal::from_text(
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
            )
            .unwrap(),
            subaccount: Some(Subaccount([1u8; 32])),
        };

        assert_eq!(account_3, expected_3);

        let mut slices = [0u8; 32];
        slices[31] = 0x01;

        let account_4 = Account {
            owner: Principal::from_text(
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
            )
            .unwrap(),
            subaccount: Some(Subaccount(slices)),
        };

        assert_eq!(
            account_4,
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i.1"
                .parse::<Account>()
                .unwrap()
        );

        let slices = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let account_5 = Account {
            owner: Principal::from_text(
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
            )
            .unwrap(),
            subaccount: Some(Subaccount(slices)),
        };

        assert_eq!(
            account_5,
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-dfxgiyy.102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .parse::<Account>()
                .unwrap()
        );
    }

    const TEST_PRINCIPAL: Principal = Principal::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 7, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    #[test]
    fn test_subaccount_derivation_path() {
        let subaccount = Subaccount::new(0);
        let account = Account::new(TEST_PRINCIPAL, None);

        assert_eq!(account.effective_subaccount(), &subaccount);

        let recover = Account::from_text(&account.to_text()).unwrap();

        assert_eq!(recover, account);

        let subaccount = Subaccount::new(0);
        let account = Account::new(TEST_PRINCIPAL, Some(subaccount.clone()));

        assert_eq!(account.effective_subaccount(), &subaccount);

        let recover = Account::from_text(&account.to_text()).unwrap();

        assert_eq!(recover, account);

        let subaccount = Subaccount::new(1);
        let account = Account::new(TEST_PRINCIPAL, Some(subaccount.clone()));

        assert_eq!(account.effective_subaccount(), &subaccount);

        let recover = Account::from_text(&account.to_text()).unwrap();

        assert_eq!(recover, account);

        let subaccount = Subaccount::new(256);
        let account = Account::new(TEST_PRINCIPAL, Some(subaccount.clone()));

        assert_eq!(account.effective_subaccount(), &subaccount);

        let recover = Account::from_text(&account.to_text()).unwrap();

        assert_eq!(recover, account);

        let subaccount = Subaccount::new(512);
        let account = Account::new(TEST_PRINCIPAL, Some(subaccount.clone()));

        assert_eq!(account.effective_subaccount(), &subaccount);

        let recover = Account::from_text(&account.to_text()).unwrap();

        assert_eq!(recover, account);

        let subaccount = Subaccount::new(400);
        let account = Account::new(TEST_PRINCIPAL, Some(subaccount.clone()));

        assert_eq!(account.effective_subaccount(), &subaccount);

        let recover = Account::from_text(&account.to_text()).unwrap();

        assert_eq!(recover, account);

        let subaccount = Subaccount::new(1024);
        let account = Account::new(TEST_PRINCIPAL, Some(subaccount.clone()));

        assert_eq!(account.effective_subaccount(), &subaccount);

        let recover = Account::from_text(&account.to_text()).unwrap();

        assert_eq!(recover, account);
    }
}
