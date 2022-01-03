mod constants;
mod header;

pub use crate::header::{validate_header, ValidateHeaderError};

type BlockHeight = u32;
