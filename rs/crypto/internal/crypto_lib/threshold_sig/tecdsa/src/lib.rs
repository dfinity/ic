#[derive(Clone, Debug)]
pub enum ThresholdSignatureError {
    InvalidPoint,
    InvalidScalar,
    CurveMismatch,
    InvalidArguments(String),
}

pub type ThresholdSignatureResult<T> = std::result::Result<T, ThresholdSignatureError>;

mod group;
mod mega;
mod seed;
mod xmd;

pub use group::*;
pub use mega::*;
pub use seed::*;
pub use xmd::*;
