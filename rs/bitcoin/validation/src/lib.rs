mod constants;
mod header;

pub use crate::header::{
    is_beyond_last_checkpoint, validate_header, HeaderStore, ValidateHeaderError,
};

type BlockHeight = u32;
