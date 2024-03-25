mod canister_alias;
mod canister_id;
mod config;
mod core;
mod domain_addr;
mod error;
mod http;
mod http_client;
mod logging;
mod metrics;
mod proxy;
mod validate;

use crate::domain_addr::DomainAddr;

pub use crate::canister_id::ResolverState;
pub use crate::config::dns_canister_config::DnsCanisterConfig;
pub use crate::core::{main, Opts};
pub use crate::proxy::{agent_handler, AppState};
pub use crate::validate::Validator;
