use candid::CandidType;
use ic_cdk::api::stable::{
    stable64_grow, stable64_read, stable64_size, stable64_write, stable_read, stable_write,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum StableOperationResult {
    Size(u64),
    Grow {
        new_pages: u64,
        result: Result<u64, ()>,
    },
    Read {
        start: u64,
        result: Vec<u8>,
    },
    Write {
        start: u64,
        contents: Vec<u8>,
    },
    Read32 {
        start: u32,
        result: Vec<u8>,
    },
    Write32 {
        start: u32,
        contents: Vec<u8>,
    },
}

impl StableOperationResult {
    pub fn perform_and_check(self) {
        match self {
            StableOperationResult::Size(expected_size) => {
                let result = stable64_size();
                assert_eq!(expected_size, result);
            }
            StableOperationResult::Grow { new_pages, result } => {
                let initial_size = stable64_size();
                let actual_result = stable64_grow(new_pages).map_err(|_| ());
                assert_eq!(result, actual_result);
                let new_size = stable64_size();
                if actual_result.is_ok() {
                    assert_eq!(new_size, initial_size + new_pages);
                } else {
                    assert_eq!(new_size, initial_size);
                }
            }
            StableOperationResult::Read { start, result } => {
                let mut actual_result = vec![0; result.len()];
                stable64_read(start, &mut actual_result);
                assert_eq!(result, actual_result);
            }
            StableOperationResult::Write { start, contents } => {
                stable64_write(start, &contents);
                let mut result = vec![0; contents.len()];
                stable64_read(start, &mut result);
                assert_eq!(contents, result);
            }
            StableOperationResult::Read32 { start, result } => {
                let mut actual_result = vec![0; result.len()];
                stable_read(start, &mut actual_result);
                assert_eq!(result, actual_result);
            }
            StableOperationResult::Write32 { start, contents } => {
                stable_write(start, &contents);
                let mut result = vec![0; contents.len()];
                stable_read(start, &mut result);
                assert_eq!(contents, result);
            }
        }
    }
}
