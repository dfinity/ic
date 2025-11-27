use std::{
    error::Error,
    fmt::{self, Display},
    str::FromStr,
};

use base32::Alphabet;
use candid::{CandidType, Deserialize, Principal, types::principal::PrincipalError};
use ic_stable_structures::{Storable, storable::Bound};
use minicbor::{Decode, Encode};
use serde::Serialize;
use std::borrow::Cow;

pub type Subaccount = [u8; 32];

pub const DEFAULT_SUBACCOUNT: &Subaccount = &[0; 32];

/// [Account](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md#value)
/// representation of ledgers supporting the ICRC-1 standard.
#[derive(Serialize, CandidType, Deserialize, Clone, Debug, Copy, Encode, Decode)]
pub struct Account {
    #[cbor(n(0), with = "icrc_cbor::principal")]
    pub owner: Principal,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub subaccount: Option<Subaccount>,
}

impl Account {
    /// The effective subaccount of an account - the subaccount if it is set, otherwise the default
    /// subaccount of all zeroes.
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
                write!(f, "invalid checksum (expected: {expected})")
            }
            ICRC1TextReprError::InvalidPrincipal(e) => write!(f, "invalid principal: {e}"),
            ICRC1TextReprError::InvalidSubaccount(e) => write!(f, "invalid subaccount: {e}"),
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
                        return Err(Self::Err::MissingChecksum);
                    }
                    Some(principal_and_checksum) => principal_and_checksum,
                    None => return Err(Self::Err::MissingChecksum),
                };
                if subaccount.starts_with('0') {
                    return Err(Self::Err::LeadingZeroesInSubaccount);
                }
                let owner = Principal::from_str(principal).map_err(Self::Err::InvalidPrincipal)?;
                let subaccount = hex::decode(format!("{subaccount:0>64}")).map_err(|e| {
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
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        minicbor::encode(self, &mut buf).expect("account encoding should always succeed");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        minicbor::decode(bytes.as_ref()).unwrap_or_else(|e| {
            panic!("failed to decode account bytes {}: {e}", hex::encode(bytes))
        })
    }

    const BOUND: Bound = Bound::Unbounded;
}

/// Maps a `Principal` to a `Subaccount`.
/// Can be used to create a separate `Subaccount` for each `Principal`.
/// Note that no canonical mapping exists from `Principal` to `Subaccount` - this is just one
/// possible mapping.
pub fn principal_to_subaccount(principal: Principal) -> Subaccount {
    let mut subaccount = [0; 32];
    let principal = principal.as_slice();
    subaccount[0] = principal.len().try_into().unwrap();
    subaccount[1..1 + principal.len()].copy_from_slice(principal);
    subaccount
}

/// Maps a `Subaccount` to a `Principal`.
/// Reverse of `principal_to_subaccount` above - if the `Subaccount` contains a `Principal` that
/// was converted using another mechanism than `principal_to_subaccount`, the result may be invalid.
///
/// # Panics
/// Panics if the `Subaccount` does not contain a valid `Principal`.
/// Use `try_from_subaccount_to_principal` if you want to handle the error instead
pub fn subaccount_to_principal(subaccount: Subaccount) -> Principal {
    let len = subaccount[0] as usize;
    Principal::from_slice(&subaccount[1..len + 1])
}

/// Tries to map a `Subaccount` to a `Principal`.
/// Reverse of `principal_to_subaccount` above - if the `Subaccount` contains a `Principal` that
/// was converted using another mechanism than `principal_to_subaccount`, the result may be invalid.
///
/// # Errors
/// * `PrincipalError::BytesTooLong()` if the length of the principal (`subaccount[0]`) is larger
///   than 29.
///
/// # Returns
/// The parsed `Principal`.
pub fn try_from_subaccount_to_principal(
    subaccount: Subaccount,
) -> Result<Principal, PrincipalError> {
    let len = subaccount[0] as usize;
    if len > Principal::MAX_LENGTH_IN_BYTES {
        return Err(PrincipalError::BytesTooLong());
    }
    Principal::try_from_slice(&subaccount[1..len + 1])
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use candid::Principal;
    use candid::types::principal::PrincipalError;
    use ic_stable_structures::Storable;
    use proptest::prelude::prop;
    use proptest::strategy::Strategy;
    use std::borrow::Cow;
    use std::str::FromStr;

    use crate::icrc1::account::{
        Account, ICRC1TextReprError, principal_to_subaccount, subaccount_to_principal,
        try_from_subaccount_to_principal,
    };

    pub fn principal_strategy() -> impl Strategy<Value = Principal> {
        let bytes_strategy = prop::collection::vec(0..=255u8, 29);
        bytes_strategy.prop_map(|bytes| Principal::from_slice(bytes.as_slice()))
    }

    pub fn account_strategy() -> impl Strategy<Value = Account> {
        let bytes_strategy = prop::option::of(prop::collection::vec(0..=255u8, 32));
        let principal_strategy = principal_strategy();
        (bytes_strategy, principal_strategy).prop_map(|(bytes, principal)| Account {
            owner: principal,
            subaccount: bytes.map(|x| x.as_slice().try_into().unwrap()),
        })
    }

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
        assert_eq!(
            account.to_string(),
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-dfxgiyy.102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
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

    #[test]
    fn test_account_serialization() {
        use proptest::{prop_assert_eq, proptest};
        proptest!(|(account in account_strategy())| {
            prop_assert_eq!(Account::from_bytes(account.to_bytes()), account);
        })
    }

    #[test]
    fn test_principal_to_subaccount() {
        use proptest::{prop_assert_eq, proptest};
        proptest!(|(principal in principal_strategy())| {
            let subaccount = principal_to_subaccount(principal);
            prop_assert_eq!(subaccount_to_principal(subaccount), principal);
        })
    }

    #[test]
    fn test_try_from_principal_to_subaccount() {
        // Should be caught by `Principal::try_from_slice`.
        assert_matches!(
            try_from_subaccount_to_principal([(Principal::MAX_LENGTH_IN_BYTES + 1) as u8; 32]),
            Err(PrincipalError::BytesTooLong())
        );
        // Should be caught by the additional check in `try_from_subaccount_to_principal`.
        assert_matches!(
            try_from_subaccount_to_principal([32u8; 32]),
            Err(PrincipalError::BytesTooLong())
        );
        use proptest::{prop_assert_eq, proptest};
        proptest!(|(principal in principal_strategy())| {
            let subaccount = principal_to_subaccount(principal);
            prop_assert_eq!(
                try_from_subaccount_to_principal(subaccount).expect("converting of valid subaccount to principal should succeed"),
                principal
            );
        })
    }

    #[test]
    #[should_panic(expected = "slice length exceeds capacity")]
    fn test_principal_error_subaccount_to_principal() {
        let principal_slice_too_large = [(Principal::MAX_LENGTH_IN_BYTES + 1) as u8; 32];
        subaccount_to_principal(principal_slice_too_large);
    }

    #[test]
    #[should_panic(expected = "range end index 256 out of range for slice of length 32")]
    fn test_index_out_of_range_subaccount_to_principal() {
        let index_out_of_range_subaccount = [0xffu8; 32];
        subaccount_to_principal(index_out_of_range_subaccount);
    }

    #[test]
    fn test_account_serialization_stability() {
        let owner =
            Principal::from_str("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
                .unwrap();
        let subaccount = Some(
            hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let mut accounts = vec![Account { owner, subaccount }];
        let mut serialized_accounts = vec![hex::decode("82581db56bf994b37ae8e79f5ce000be1727a6060ae4eef24736b7cc999c3c0258200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap()];
        let owner =
            Principal::from_str("gjfkw-yiolw-ncij7-yzhg2-gq6ec-xi6jy-feyni-g26f4-x7afk-thx6z-6ae")
                .unwrap();
        let subaccount = Some(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        accounts.push(Account { owner, subaccount });
        serialized_accounts.push(hex::decode("82581d0e5d9a2427f8c9cda343c415d1e4e0a4c3506d78bcbfc0554cf7f67c0258200000000000000000000000000000000000000000000000000000000000000000").unwrap());

        let owner = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
        let subaccount = None;
        accounts.push(Account { owner, subaccount });
        serialized_accounts.push(hex::decode("8149efcdab000000000001").unwrap());

        for (i, account) in accounts.iter().enumerate() {
            assert_eq!(account.to_bytes(), serialized_accounts[i].clone());
            assert_eq!(
                *account,
                Account::from_bytes(Cow::Owned(serialized_accounts[i].clone()))
            );
        }
    }
}
