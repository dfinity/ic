use std::{borrow::Cow, fmt::Display};

use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;

const BYTE: u32 = 1;
const KB: u32 = 1024 * BYTE;

const ENCRYPTED_PRIVATE_KEY_LEN: u32 = KB; // 1 * KB
const ENCRYPTED_CERTIFICATE_LEN: u32 = 8 * KB;
const ENCRYPTED_PAIR_LEN: u32 = ENCRYPTED_PRIVATE_KEY_LEN + ENCRYPTED_CERTIFICATE_LEN;

pub type Id = String;

pub const LABEL_DOMAINS: &[u8] = b"custom_domains";
pub const LEFT_GUARD: &str = "0";
pub const RIGHT_GUARD: &str = "z";

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct EncryptedPair(
    #[serde(with = "serde_bytes")] pub Vec<u8>, // PrivateKey
    #[serde(with = "serde_bytes")] pub Vec<u8>, // Certificate
);

impl Storable for EncryptedPair {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: ENCRYPTED_PAIR_LEN,
        is_fixed_size: false,
    };
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Default, CandidType, Deserialize)]
pub struct BoundedString<const N: usize>(String);

impl<const N: usize> Display for BoundedString<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a, const N: usize, T> From<T> for BoundedString<N>
where
    T: Into<Cow<'a, str>>,
{
    fn from(v: T) -> Self {
        let v: Cow<str> = v.into();
        let mut v = v.into_owned();

        // Trim the string to bounded size
        v.truncate(floor_char_boundary(&v, N));

        Self(v)
    }
}

impl<const N: usize> BoundedString<N> {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<const N: usize> From<BoundedString<N>> for String {
    fn from(v: BoundedString<N>) -> Self {
        v.0
    }
}

// Copy-paste from https://doc.rust-lang.org/src/core/str/mod.rs.html#258
// Needed because it's still experimental
fn floor_char_boundary(v: &str, index: usize) -> usize {
    if index >= v.len() {
        v.len()
    } else {
        let lower_bound = index.saturating_sub(3);
        (lower_bound..=index)
            .rev()
            .find(|&i| v.is_char_boundary(i))
            .unwrap()
    }
}

impl<const N: usize> Storable for BoundedString<N> {
    fn to_bytes(&self) -> Cow<[u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        String::from_bytes(bytes).into()
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: N as u32,
        is_fixed_size: false,
    };
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType, Deserialize)]
pub struct Name(String);

// NAME_MAX_LEN is the maximum length a name is allowed to have.
// Based on https://en.wikipedia.org/wiki/Domain_name#Domain_name_syntax
pub const NAME_MAX_LEN: u32 = 253;

#[derive(PartialEq, Debug, thiserror::Error)]
pub enum NameError {
    #[error("Name has size '{0}' but must not exceed size {}", NAME_MAX_LEN)]
    InvalidSize(usize),

    #[error("domains with a dot suffix are not supported")]
    DotSuffix,

    #[error("Name is not a valid domain: '{0}'")]
    InvalidDomain(String),
}

impl From<Name> for String {
    fn from(name: Name) -> Self {
        name.0
    }
}

impl TryFrom<&str> for Name {
    type Error = NameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > NAME_MAX_LEN as usize {
            return Err(NameError::InvalidSize(value.len()));
        }

        if value.ends_with('.') {
            return Err(NameError::DotSuffix);
        }

        // Ensure it's a valid domain name
        let name = addr::parse_domain_name(value)
            .map_err(|err| NameError::InvalidDomain(err.to_string()))?;

        if name.as_str().matches('.').count() == 0 {
            return Err(NameError::InvalidDomain(format!(
                "domain is not supported: {value}"
            )));
        }

        Ok(Self(name.as_str().into()))
    }
}

impl Storable for Name {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: NAME_MAX_LEN,
        is_fixed_size: false,
    };
}

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub enum State {
    #[serde(rename = "failed")]
    Failed(BoundedString<127>),

    #[serde(rename = "pendingOrder")]
    PendingOrder,

    #[serde(rename = "pendingChallengeResponse")]
    PendingChallengeResponse,

    #[serde(rename = "pendingAcmeApproval")]
    PendingAcmeApproval,

    #[serde(rename = "available")]
    Available,
}

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub struct Registration {
    pub name: Name,
    pub canister: Principal,
    pub state: State,
}

impl Storable for Registration {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }

    const BOUND: Bound = Bound::Bounded {
        // The MAX_SIZE for Registration was determined by building the biggest possible
        // registration and calculating it's resulting Candid encoded size.
        // This can be found below under the `max_registration_size` test.
        // The final MAX_SIZE we use here provided plenty of padding for future growth
        max_size: 1024,
        is_fixed_size: false,
    };
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ExportPackage {
    pub id: Id,
    pub name: Name,
    pub canister: Principal,
    pub pair: EncryptedPair,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum CreateRegistrationError {
    Duplicate(Id),
    NameError(String),
    RateLimited(String),
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum CreateRegistrationResponse {
    Ok(Id),
    Err(CreateRegistrationError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum GetRegistrationError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum GetRegistrationResponse {
    Ok(Registration),
    Err(GetRegistrationError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum UpdateType {
    Canister(Principal),
    State(State),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum UpdateRegistrationError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum UpdateRegistrationResponse {
    Ok(()),
    Err(UpdateRegistrationError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum RemoveRegistrationError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum RemoveRegistrationResponse {
    Ok(()),
    Err(RemoveRegistrationError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum GetCertificateError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum GetCertificateResponse {
    Ok(EncryptedPair),
    Err(GetCertificateError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum UploadCertificateError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum UploadCertificateResponse {
    Ok(()),
    Err(UploadCertificateError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ExportCertificatesError {
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ExportCertificatesResponse {
    Ok(Vec<ExportPackage>),
    Err(ExportCertificatesError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct IcCertificate {
    #[serde(with = "serde_bytes")]
    pub cert: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub tree: Vec<u8>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ExportCertificatesCertifiedResponse {
    Ok((Vec<ExportPackage>, IcCertificate)),
    Err(ExportCertificatesError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum QueueTaskError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum QueueTaskResponse {
    Ok(()),
    Err(QueueTaskError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum PeekTaskError {
    NoTasksAvailable,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum PeekTaskResponse {
    Ok(Id),
    Err(PeekTaskError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum DispenseTaskError {
    NoTasksAvailable,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum DispenseTaskResponse {
    Ok(Id),
    Err(DispenseTaskError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ModifyAllowedPrincipalError {
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ModifyAllowedPrincipalResponse {
    Ok(()),
    Err(ModifyAllowedPrincipalError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ListAllowedPrincipalsError {
    Unauthorized,
    UnexpectedError(String),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ListAllowedPrincipalsResponse {
    Ok(Vec<Principal>),
    Err(ListAllowedPrincipalsError),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InitArg {
    #[serde(rename = "rootPrincipals")]
    pub root_principals: Vec<Principal>,
    #[serde(rename = "idSeed")]
    pub id_seed: u128,
    #[serde(rename = "registrationExpirationTtl")]
    pub registration_expiration_ttl: Option<u64>,
    #[serde(rename = "inProgressTtl")]
    pub in_progress_ttl: Option<u64>,
    #[serde(rename = "managementTaskInterval")]
    pub management_task_interval: Option<u64>,
}

// Http Interface (for metrics)

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HeaderField(pub String, pub String);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderField>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_bytes_is_ok() {
        #[derive(Clone, Debug, CandidType, Deserialize)]
        struct WithSerdeBytes {
            #[serde(with = "serde_bytes")]
            field: Vec<u8>,
        }
        #[derive(Clone, Debug, CandidType, Deserialize)]
        struct WithoutSerdeBytes {
            field: Vec<u8>,
        }
        let some_bytes: Vec<u8> = [200, 201, 202].to_vec();
        let struct1 = WithSerdeBytes {
            field: some_bytes.clone(),
        };
        let struct2 = WithoutSerdeBytes { field: some_bytes };
        assert_eq!(Encode!(&struct1).unwrap(), Encode!(&struct2).unwrap());
    }

    #[test]
    fn name_ok_idna() {
        assert_eq!(Name::try_from("rüdi.com"), Ok(Name("rüdi.com".to_string())),);
    }

    #[test]
    fn name_invalid_size() {
        let n = (NAME_MAX_LEN + 1) as usize;

        assert_eq!(
            Name::try_from("a".repeat(n).as_str()),
            Err(NameError::InvalidSize(n)),
        );
    }

    #[test]
    fn name_invalid_format() {
        assert_eq!(
            Name::try_from(""),
            Err(NameError::InvalidDomain(
                "'' contains an empty label".to_string()
            )),
        );

        assert_eq!(
            Name::try_from("exa\nmple.com"),
            Err(NameError::InvalidDomain(
                "'exa\nmple.com' contains an illegal character".to_string()
            )),
        );

        assert_eq!(
            Name::try_from("example"),
            Err(NameError::InvalidDomain(
                "domain is not supported: example".to_string()
            )),
        );

        assert_eq!(Name::try_from("example."), Err(NameError::DotSuffix),);
    }

    #[test]
    fn bounded_string() {
        assert_eq!(BoundedString::<0>::from("").as_str(), "");
        assert_eq!(BoundedString::<0>::from("123").as_str(), "");
        assert_eq!(BoundedString::<1>::from("123").as_str(), "1");
        assert_eq!(BoundedString::<3>::from("123").as_str(), "123");
        assert_eq!(BoundedString::<4>::from("123").as_str(), "123");
    }

    const MAX_REGISTRATION_SIZE: usize = 474;

    #[test]
    fn max_registration_size() {
        let max = [
            Registration {
                name: Name(String::from_iter(vec!['a'; NAME_MAX_LEN as usize])),
                canister: Principal::from_slice(&[0xFF; 29]),
                state: State::Failed(String::from_iter(vec!['a'; 127]).into()),
            },
            Registration {
                name: Name(String::from_iter(vec!['a'; NAME_MAX_LEN as usize])),
                canister: Principal::from_slice(&[0xFF; 29]),
                state: State::Failed(String::from_iter(vec!['a'; 128]).into()),
            },
        ];

        for v in max {
            assert_eq!(v.to_bytes().len(), MAX_REGISTRATION_SIZE);
        }
    }

    #[test]
    fn non_max_registration_size() {
        let non_max = [
            Registration {
                name: Name(String::from_iter(vec!['a'; NAME_MAX_LEN as usize - 1])),
                canister: Principal::from_slice(&[0xFF; 29]),
                state: State::Failed(String::from_iter(vec!['a'; 127]).into()),
            },
            Registration {
                name: Name(String::from_iter(vec!['a'; NAME_MAX_LEN as usize])),
                canister: Principal::from_slice(&[0xFF; 28]),
                state: State::Failed(String::from_iter(vec!['a'; 127]).into()),
            },
            Registration {
                name: Name(String::from_iter(vec!['a'; NAME_MAX_LEN as usize])),
                canister: Principal::from_slice(&[0xFF; 29]),
                state: State::Failed(String::from_iter(vec!['a'; 126]).into()),
            },
        ];

        for v in non_max {
            assert!(v.to_bytes().len() < MAX_REGISTRATION_SIZE);
        }
    }
}
