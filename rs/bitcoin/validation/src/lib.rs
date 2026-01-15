mod constants;
pub mod doge;
mod header;
#[cfg(test)]
mod tests;

pub use crate::constants::max_target;
pub use crate::header::{
    AuxPowHeaderValidator, HeaderStore, HeaderValidator, ValidateAuxPowHeaderError,
    ValidateHeaderError, validate_header,
};

type BlockHeight = u32;
