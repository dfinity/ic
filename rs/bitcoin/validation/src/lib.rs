mod constants;
mod header;

pub use crate::constants::max_target;
pub use crate::header::{validate_header, HeaderStore, ValidateHeaderError};

type BlockHeight = u32;
