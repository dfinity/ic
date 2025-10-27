use crate::page_map;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;

#[derive(Clone, ValidateEq)]
pub struct LogMemoryStore {
    #[validate_eq(Ignore)]
    pub page_map: PageMap,
}

impl LogMemoryStore {
    pub fn new(page_map: PageMap) -> Self {
        Self { page_map }
    }
}
