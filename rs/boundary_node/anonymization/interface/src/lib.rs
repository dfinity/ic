use candid::{CandidType, Deserialize, Principal};

#[derive(CandidType, Deserialize)]
pub struct Pair(pub Principal, #[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(CandidType, Deserialize)]
pub struct InitArg {}

#[derive(CandidType, Deserialize)]
pub enum RegisterError {
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum RegisterResponse {
    Ok,
    Err(RegisterError),
}

#[derive(CandidType, Deserialize)]
pub enum LeaderMode {
    Bootstrap,
    Refresh,
}

#[derive(CandidType, Deserialize)]
pub enum QueryError {
    Unauthorized,
    Unavailable,
    LeaderDuty(LeaderMode, Vec<Pair>),
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum QueryResponse {
    Ok(Vec<u8>),
    Err(QueryError),
}

#[derive(CandidType, Deserialize)]
pub enum SubmitError {
    Unauthorized,
    UnexpectedError(String),
}

#[derive(CandidType, Deserialize)]
pub enum SubmitResponse {
    Ok,
    Err(SubmitError),
}

// Http Interface (for metrics)

#[derive(CandidType, Deserialize)]
pub struct HeaderField(pub String, pub String);

#[derive(CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderField>,

    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,

    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}
