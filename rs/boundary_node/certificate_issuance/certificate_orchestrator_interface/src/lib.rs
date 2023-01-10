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

#[derive(Debug, Clone, Deserialize)]
pub struct Name(String);

pub const NAME_MAX_LEN: u32 = 64;

#[derive(Debug, thiserror::Error)]
pub enum NameError {
    #[error("Name has size '{0}' but must not exceed size {}", NAME_MAX_LEN)]
    InvalidSize(usize),
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

        Ok(Self(value.into()))
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

#[derive(Debug, CandidType, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, CandidType, Deserialize)]
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
