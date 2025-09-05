mod constants;
pub mod doge;
mod header;
#[cfg(test)]
mod tests;

pub use crate::constants::max_target;
pub use crate::header::{validate_header, AuxPowHeaderValidator, HeaderStore, ValidateHeaderError};

type BlockHeight = u32;
