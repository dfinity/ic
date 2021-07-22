/// This canister is used in the testcase 5_2. The canister stores a vector of
/// variable length, and the number of times the canister update method has
/// been called.
use dfn_macro::{query, update};
use lazy_static::lazy_static;
use mersenne_twister::MT19937;
use rand::{Rng, SeedableRng};
use std::sync::Mutex;

/// Size of data vector in canister, 128 MB
/// 256 MB ends with a timeout
const VECTOR_LENGTH: usize = 128 * 1024 * 1024;

lazy_static! {
    static ref V_DATA: Mutex<Vec<u8>> = Mutex::new(vec![0; VECTOR_LENGTH]);
    static ref V_DATA_1: Mutex<Vec<u8>> = Mutex::new(vec![1; VECTOR_LENGTH]);
    static ref V_DATA_2: Mutex<Vec<u8>> = Mutex::new(vec![2; VECTOR_LENGTH]);
    static ref V_DATA_3: Mutex<Vec<u8>> = Mutex::new(vec![3; VECTOR_LENGTH]);
    static ref V_DATA_4: Mutex<Vec<u8>> = Mutex::new(vec![4; VECTOR_LENGTH]);
    static ref V_DATA_5: Mutex<Vec<u8>> = Mutex::new(vec![5; VECTOR_LENGTH]);
    static ref V_DATA_6: Mutex<Vec<u8>> = Mutex::new(vec![6; VECTOR_LENGTH]);
    static ref V_DATA_7: Mutex<Vec<u8>> = Mutex::new(vec![7; VECTOR_LENGTH]);
    static ref V_DATA_8: Mutex<Vec<u8>> = Mutex::new(vec![8; VECTOR_LENGTH]);
    static ref NUM_CHANGED: Mutex<u64> = Mutex::new(0_u64);
}

/// Changes every 1023rd byte in `V_DATA` to a random value.
///
/// Returns the number of times it has been called.
#[update]
async fn change_state(seed: u32) -> Result<u64, String> {
    let mut state = V_DATA.lock().unwrap();
    let mut num_changed = NUM_CHANGED.lock().unwrap();
    let mut rng = MT19937::from_seed(seed);

    for index in (0..VECTOR_LENGTH).step_by(1023) {
        state[index] = rng.next_u32() as u8;
    }
    *num_changed += 1;
    Ok(*num_changed)
}

/// Expands state by access the indexed V_DATA and changes every 1,048,576th
/// byte (1 MiB) to a random value.
///
/// Returns the number of times it has been called.
#[update]
async fn expand_state(index: u32, seed: u32) -> Result<u64, String> {
    let mut num_changed = NUM_CHANGED
        .lock()
        .expect("Could not lock NUM_CHANGED mutex");
    let mut rng = MT19937::from_seed(seed);
    let mut state = match index % 8 {
        1 => V_DATA_1.lock().expect("Could not lock V_DATA_1 mutex"),
        2 => V_DATA_2.lock().expect("Could not lock V_DATA_2 mutex"),
        3 => V_DATA_3.lock().expect("Could not lock V_DATA_3 mutex"),
        4 => V_DATA_4.lock().expect("Could not lock V_DATA_4 mutex"),
        5 => V_DATA_5.lock().expect("Could not lock V_DATA_5 mutex"),
        6 => V_DATA_6.lock().expect("Could not lock V_DATA_6 mutex"),
        7 => V_DATA_7.lock().expect("Could not lock V_DATA_7 mutex"),
        _ => V_DATA_8.lock().expect("Could not lock V_DATA_8 mutex"),
    };
    let offset = rng.next_u32() as u16;
    for ind in (offset as usize..VECTOR_LENGTH).step_by(1_048_576) {
        state[ind] = rng.next_u32() as u8;
    }
    *num_changed += 1;
    Ok(*num_changed)
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
