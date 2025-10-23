use crate::page_map;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;

#[derive(Clone, ValidateEq)]
pub struct LogMemoryStore {
    #[validate_eq(Ignore)]
    pub buffer: page_map::Buffer,
}

impl LogMemoryStore {
    pub fn new(buffer: page_map::Buffer) -> Self {
        Self { buffer }
    }
}
