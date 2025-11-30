use ic_cdk::stable::{
    WASM_PAGE_SIZE_IN_BYTES as PAGE_SIZE, stable_grow, stable_size, stable_write,
};
/// This canister is used in the testcase 5_2. The canister stores a vector of
/// variable length, and the number of times the canister update method has
/// been called.
use ic_cdk::{query, update};
use lazy_static::lazy_static;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::sync::Mutex;

/// Size of data vector in canister, 128 MB
const VECTOR_LENGTH: usize = 128 * 1024 * 1024;

lazy_static! {
    static ref V_DATA: Mutex<Vec<u8>> = Mutex::new(vec![0; VECTOR_LENGTH]);
    static ref NUM_CHANGED: Mutex<u64> = Mutex::new(0_u64);
}

/// Changes every 1023rd byte in `V_DATA` to a random value.
///
/// Returns the number of times it has been called.
#[update]
async fn change_state(seed: u32) -> Result<u64, String> {
    let mut state = V_DATA.lock().unwrap();
    let mut num_changed = NUM_CHANGED.lock().unwrap();
    let mut rng = SmallRng::seed_from_u64(seed as u64);

    for index in (0..VECTOR_LENGTH).step_by(1023) {
        state[index] = rng.r#gen();
    }
    *num_changed += 1;
    Ok(*num_changed)
}

fn grow_stable_memory_to(target_bytes: u64) -> Result<(), String> {
    let current_num_pages = stable_size();
    if (current_num_pages * PAGE_SIZE) >= target_bytes {
        return Ok(());
    }
    stable_grow(target_bytes.div_ceil(PAGE_SIZE) - current_num_pages)
        .map_or_else(|e| Err(e.to_string()), |_| Ok(()))
}

/// Writes random data to stable memory at the given offset and length.
///
/// Note: This function not only writes to stable memory but also changes the
/// canister heap, as `V_DATA` is used as a buffer and gets filled with random bytes.
/// This is good for state sync tests as both stable memory and heap can be covered.
#[update]
async fn write_random_data(offset: u64, length: u64, seed: u64) -> Result<(), String> {
    grow_stable_memory_to(offset + length)?;

    let mut rng = SmallRng::seed_from_u64(seed);
    let mut buffer = V_DATA.lock().unwrap();
    let mut current_offset = offset;
    let mut remaining = length as usize;

    while remaining > 0 {
        let write_size = remaining.min(buffer.len());
        rng.fill(&mut buffer[..write_size]);
        stable_write(current_offset, &buffer[..write_size]);
        current_offset += write_size as u64;
        remaining -= write_size;
    }
    Ok(())
}

/// Method to query element index of the vector, return first element if index
/// out of bounds
#[query]
async fn read_state(index: usize) -> Result<u8, String> {
    let state = V_DATA.lock().unwrap();
    if index < state.len() {
        Ok(state[index])
    } else {
        Ok(state[0])
    }
}

fn main() {}
