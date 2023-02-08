use std::borrow::Cow;

use candid::{
    types::{Serializer, Type},
    CandidType, Decode, Deserialize, Encode, Principal,
};
use ic_stable_structures::Storable;

pub type Id = String;

#[derive(CandidType, Deserialize)]
pub struct EncryptedPair(
    pub Vec<u8>, // PrivateKey
    pub Vec<u8>, // Certificate
);

impl Storable for EncryptedPair {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Name(String);

// NAME_MAX_LEN is the maximum length a name is allowed to have.
// Based on https://en.wikipedia.org/wiki/Domain_name#Domain_name_syntax
pub const NAME_MAX_LEN: u32 = 253;

#[derive(Debug, PartialEq, thiserror::Error)]
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

impl CandidType for Name {
    fn idl_serialize<S: Serializer>(&self, serializer: S) -> Result<(), S::Error> {
        String::idl_serialize(&self.0, serializer)
    }

    fn _ty() -> Type {
        Type::Text
    }
}

impl Storable for Name {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}

#[derive(Debug, CandidType, Clone, PartialEq, Deserialize)]
pub enum State {
    #[serde(rename = "failed")]
    Failed(String),

    #[serde(rename = "pendingOrder")]
    PendingOrder,

    #[serde(rename = "pendingChallengeResponse")]
    PendingChallengeResponse,

    #[serde(rename = "pendingAcmeApproval")]
    PendingAcmeApproval,

    #[serde(rename = "available")]
    Available,
}

impl Storable for State {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}

#[derive(Debug, CandidType, Clone, PartialEq, Deserialize)]
pub struct Registration {
    pub name: Name,
    pub canister: Principal,
    pub state: State,
}

impl Storable for Registration {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}

#[derive(CandidType, Deserialize)]
pub struct ExportPackage {
    pub name: Name,
    pub canister: Principal,
    pub pair: EncryptedPair,
}

#[derive(CandidType, Deserialize)]
pub enum CreateRegistrationError {
    Duplicate(Id),
    NameError(String),
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum CreateRegistrationResponse {
    Ok(Id),
    Err(CreateRegistrationError),
}

#[derive(CandidType, Deserialize)]
pub enum GetRegistrationError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum GetRegistrationResponse {
    Ok(Registration),
    Err(GetRegistrationError),
}

#[derive(CandidType, Deserialize)]
pub enum UpdateType {
    Canister(Principal),
    State(State),
}

#[derive(CandidType, Deserialize)]
pub enum UpdateRegistrationError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum UpdateRegistrationResponse {
    Ok(()),
    Err(UpdateRegistrationError),
}

#[derive(CandidType, Deserialize)]
pub enum RemoveRegistrationError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum RemoveRegistrationResponse {
    Ok(()),
    Err(RemoveRegistrationError),
}

#[derive(CandidType, Deserialize)]
pub enum UploadCertificateError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum UploadCertificateResponse {
    Ok(()),
    Err(UploadCertificateError),
}

#[derive(CandidType, Deserialize)]
pub enum ExportCertificatesError {
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum ExportCertificatesResponse {
    Ok(Vec<ExportPackage>),
    Err(ExportCertificatesError),
}

#[derive(CandidType, Deserialize)]
pub enum QueueTaskError {
    NotFound,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum QueueTaskResponse {
    Ok(()),
    Err(QueueTaskError),
}

#[derive(CandidType, Deserialize)]
pub enum PeekTaskError {
    NoTasksAvailable,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum PeekTaskResponse {
    Ok(Id),
    Err(PeekTaskError),
}

#[derive(CandidType, Deserialize)]
pub enum DispenseTaskError {
    NoTasksAvailable,
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum DispenseTaskResponse {
    Ok(Id),
    Err(DispenseTaskError),
}

#[derive(CandidType, Deserialize)]
pub enum ModifyAllowedPrincipalError {
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum ModifyAllowedPrincipalResponse {
    Ok(()),
    Err(ModifyAllowedPrincipalError),
}

#[derive(CandidType, Deserialize)]
pub enum ListAllowedPrincipalsError {
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum ListAllowedPrincipalsResponse {
    Ok(Vec<Principal>),
    Err(ListAllowedPrincipalsError),
}

// Http Interface (for metrics)

#[derive(CandidType, Deserialize)]
pub struct HeaderField(pub String, pub String);

#[derive(CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
