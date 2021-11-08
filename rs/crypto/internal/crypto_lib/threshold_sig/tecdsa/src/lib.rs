#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThresholdEcdsaError {
    InvalidPoint,
    InvalidScalar,
    CurveMismatch,
    InvalidFieldElement,
    InvalidArguments(String),
}

pub type ThresholdEcdsaResult<T> = std::result::Result<T, ThresholdEcdsaError>;

mod fe;
mod group;
mod hash2curve;
mod mega;
mod poly;
mod seed;
mod xmd;

pub use fe::*;
pub use group::*;
pub use mega::*;
pub use poly::*;
pub use seed::*;
pub use xmd::*;
