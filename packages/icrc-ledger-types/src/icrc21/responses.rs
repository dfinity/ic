use super::requests::ConsentMessageMetadata;
use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineDisplayPage {
    pub lines: Vec<String>,
}

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsentMessage {
    GenericDisplayMessage(String),
    LineDisplayMessage { pages: Vec<LineDisplayPage> },
}

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentInfo {
    pub consent_message: ConsentMessage,
    pub metadata: ConsentMessageMetadata,
}
