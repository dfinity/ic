use candid::CandidType;
use serde::de::DeserializeOwned;

pub trait Request: CandidType + Send {
    type Response: CandidType + DeserializeOwned;
    const METHOD: &'static str;

    /// Indicates whether the request should be called as a query or an update
    const UPDATE: bool;
}
