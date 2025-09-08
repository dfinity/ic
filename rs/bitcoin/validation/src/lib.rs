mod constants;
mod header;

pub use crate::constants::max_target;
pub use crate::header::{HeaderStore, ValidateHeaderError, validate_header};

type BlockHeight = u32;
