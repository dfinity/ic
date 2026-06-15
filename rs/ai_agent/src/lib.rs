//! IC AI agent orchestration library.
//!
//! Lightweight HTTP API exposing single-turn (`/v1/agent/run`) and
//! multi-turn (`/v1/agent/chat`) agent endpoints, backed by the
//! [`rig`](https://docs.rig.rs/) library. Gemini is the default and currently
//! only supported provider; new providers are added by extending
//! [`providers::AiProvider`].

pub mod config;
pub mod handlers;
pub mod models;
pub mod providers;
pub mod router;
pub mod sessions;
pub mod state;
pub mod tools;
