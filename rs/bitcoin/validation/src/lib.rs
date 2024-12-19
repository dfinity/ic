mod constants;
mod header;

pub use crate::header::{validate_header, HeaderStore, ValidateHeaderError};

type BlockHeight = u32;
