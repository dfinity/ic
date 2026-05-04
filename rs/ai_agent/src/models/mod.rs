//! Wire types for HTTP request/response bodies.

pub mod request;
pub mod response;

pub use request::{ChatMessage, ChatRequest, RunRequest};
pub use response::{ChatResponse, ErrorBody, HealthResponse, RunResponse};
