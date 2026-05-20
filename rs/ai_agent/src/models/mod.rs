//! Wire types for HTTP request/response bodies.

pub mod request;
pub mod response;

pub use request::{ChatRequest, RunRequest, ToolsConfigRequest};
pub use response::{
    ChatResponse, ClearResponse, ErrorBody, HealthResponse, RunResponse, ToolsConfigResponse,
};
