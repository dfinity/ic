//! Verbatim from `dfx_core::error::get_user_home`.
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GetUserHomeError {
    #[error("Cannot find home directory (no HOME environment variable).")]
    NoHomeInEnvironment(),
}
