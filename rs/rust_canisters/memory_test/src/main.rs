//! This module contains a canister used for testing memory operations.

use dfn_core::{
    api::{self, ic0, trap_with},
    stable,
};
use rand::Rng;
use rand_pcg::Lcg64Xsh32;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::mem;

const ELEMENT_SIZE: usize = mem::size_of::<u64>();
const MEMORY_SIZE: usize = 1 << 30; // 1GiB, can't exceed 4GB.
const MEMORY_LEN: usize = MEMORY_SIZE / ELEMENT_SIZE;
// Note: the WASM target is 32 bit, so we need to explicitly use u64, not usize
const STABLE_MEMORY_SIZE: u64 = 6 * (1 << 30); // 6GiB.
const WASM_PAGE_SIZE_IN_BYTES: usize = 64 * 1024; // 64 KiB
const PAGE_SIZE: usize = 4096;

/// All methods get this struct as an argument encoded in a JSON string.
/// Each method performs some memory operation like `read`, `write`,
/// `read_write`, `copy` on some memory region.
///
/// # Fields
///
/// * `repeat` - optional number of iterations (1 by default).
/// * `address` - optional start address of the memory region (random by default).
/// * `size` - size of the memory region in bytes.
/// * `step` - optional interval between reads/writes in bytes (contig. by default).
/// * `value` - optional value to assert/write (no assertion/random by default)
#[derive(Serialize, Deserialize, Debug)]
struct Operation {
    repeat: Option<usize>,
    // Note: the WASM target is 32 bit, so we need to explicitly use u64, not usize
    address: Option<u64>,
    size: u64,
    step: Option<usize>,
    value: Option<u8>,
}

/// The result of `read` and `read_write` operations. Represents the sum
/// of all 8 byte words in the given memory region.
#[derive(Serialize, Deserialize)]
struct Sum {
    value: u64,
}

thread_local! {
    /// A random number generator used to perform writes/reads to/from
    /// memory at random offsets.
    static RNG: RefCell<Lcg64Xsh32> = RefCell::new(Lcg64Xsh32::new(0xcafe_f00d_d15e_a5e5, 0x0a02_bdbf_7bb3_c0a7));

    /// Pages accessed by read/write methods.
    static MEMORY: RefCell<Vec<u64>> = const { RefCell::new(vec![]) };
}

fn arg_data() -> Vec<u8> {
    let len = unsafe { ic0::msg_arg_data_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::msg_arg_data_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    bytes
}

fn operation_from_args() -> Operation {
    let data = arg_data();
    // To quick and dirty support `dfx` tool, we also try to parse [8..] (skipping DIDL..q.).
    // TODO: support Rust CDK?
    // Usage:
    //    dfx canister --network "${NODE}" call "${CANISTER_ID}" query_read '("{\"size\": 1}")'
    // Then to decode return blob value:
    //    echo 0x3230 | xxd -rp
    match serde_json::from_slice(&data).or_else(|_| serde_json::from_slice(&data[8..])) {
        Ok(op) => op,
        Err(err) => {
            trap_with(&format!(
                "Failed to parse Operation from JSON.\nJSON: {}\nError: {:?}",
                String::from_utf8_lossy(&data),
                err,
            ));
        }
    }
}

fn rand<T>(low: T, high: T) -> T
where
    T: rand::distributions::uniform::SampleUniform + std::cmp::PartialOrd,
{
    RNG.with(|rng| rng.borrow_mut().gen_range(low..high))
}

/// Reads and sums up all 8-byte values from the given memory region.
///
/// # Arguments
///
/// * `operation.repeat` - optional number of iterations (1 by default).
/// * `operation.address` - optional start address of the memory region (random by default).
/// * `operation.size` - size of the memory region in bytes.
/// * `operation.step` - optional interval between reads in bytes (contig. by default).
/// * `operation.value` - optional value to assert (no assertion by default)
fn read() {
    let operation = operation_from_args();
    let mut sum = 0;

    let repeat = operation.repeat.unwrap_or(1);
    let step = operation.step.unwrap_or(ELEMENT_SIZE) / ELEMENT_SIZE;
    // Address can't exceed 4GiB WASM memory
    let len = operation.size;
    let src = operation
        .address
        .unwrap_or_else(|| rand(0, MEMORY_SIZE as u64 - len));
    assert!(src + len <= MEMORY_SIZE as u64);
    let len = len as usize / ELEMENT_SIZE;
    let src = src as usize / ELEMENT_SIZE;

    MEMORY.with(|memory| {
        let memory_ref = memory.borrow();
        let memory = memory_ref.as_slice();
        for _ in 0..repeat {
            for i in (src..src + len).step_by(step) {
                let value = memory[i];
                if let Some(expected_value) = operation.value {
                    if expected_value != value as u8 {
                        trap_with(&format!(
                            "Value mismatch at {}, expected {}, got {}",
                            i * ELEMENT_SIZE,
                            expected_value,
                            value
                        ));
                    }
                }
                sum += value;
            }
        }
    });
    api::reply(sum.to_string().as_bytes());
}

/// Writes 8-byte values into the given memory region.
///
/// # Arguments
///
/// * `operation.repeat` - optional number of iterations (1 by default).
/// * `operation.address` - optional start address of the memory region (random by default).
/// * `operation.size` - size of the memory region in bytes.
/// * `operation.step` - optional interval between writes in bytes (contig. by default).
/// * `operation.value` - optional value to write (random by default)
fn write() {
    let operation = operation_from_args();

    let repeat = operation.repeat.unwrap_or(1);
    let step = operation.step.unwrap_or(ELEMENT_SIZE) / ELEMENT_SIZE;
    let value = operation.value.unwrap_or_else(|| rand(0, u8::MAX));
    // Address can't exceed 4GiB WASM memory
    let len = operation.size;
    let dst = operation
        .address
        .unwrap_or_else(|| rand(0, MEMORY_SIZE as u64 - len));
    assert!(dst + len <= MEMORY_SIZE as u64);
    let len = len as usize / ELEMENT_SIZE;
    let dst = dst as usize / ELEMENT_SIZE;
    MEMORY.with(|memory| {
        let mut memory_ref = memory.borrow_mut();
        let memory = memory_ref.as_mut_slice();
        for _ in 0..repeat {
            for i in (dst..dst + len).step_by(step) {
                memory[i] = value as u64;
            }
        }
    });
    api::reply(&[]);
}

/// Combines the read and write operations above.
///
/// # Arguments:
///
/// * `operation.repeat` - optional number of iterations (1 by default).
/// * `operation.address` - optional start address of the memory region (random by default).
/// * `operation.size` - size of the memory region in bytes.
/// * `operation.step` - optional interval between writes in bytes (contig. by default).
/// * `operation.value` - optional value to write (random by default)
fn read_write() {
    let operation = operation_from_args();
    let mut sum = 0;

    let repeat = operation.repeat.unwrap_or(1);
    let step = operation.step.unwrap_or(ELEMENT_SIZE) / ELEMENT_SIZE;
    let value = operation.value.unwrap_or_else(|| rand(0, u8::MAX));
    // Address can't exceed 4GiB WASM memory
    let len = operation.size;
    let src = operation
        .address
        .unwrap_or_else(|| rand(0, MEMORY_SIZE as u64 - len));
    assert!(src + len <= MEMORY_SIZE as u64);
    let len = len as usize / ELEMENT_SIZE;
    let src = src as usize / ELEMENT_SIZE;
    MEMORY.with(|memory| {
        let mut memory_ref = memory.borrow_mut();
        let memory = memory_ref.as_mut_slice();
        for _ in 0..repeat {
            for i in (src..src + len).step_by(step) {
                sum += memory[i];
                memory[i] = value as u64;
            }
        }
    });
    api::reply(sum.to_string().as_bytes());
}

/// Reads and sums up all 8-byte values from the given stable memory region.
///
/// # Arguments
///
/// * `operation.repeat` - optional number of iterations (1 by default).
/// * `operation.address` - optional start address of the memory region (random by default).
/// * `operation.size` - size of the memory region in bytes.
/// * `operation.step` - optional interval between reads in bytes (contig. by default).
/// * `operation.value` - optional value to assert (no assertion by default)
fn stable_read() {
    let operation = operation_from_args();
    let mut sum = 0;

    let repeat = operation.repeat.unwrap_or(1);
    let step = operation.step.unwrap_or(ELEMENT_SIZE);
    let len = operation.size;
    for _ in 0..repeat {
        MEMORY.with(|memory| {
            let mut refmut = memory.borrow_mut();
            #[allow(unused_assignments)]
            let mut buf = vec![].as_mut_slice();
            unsafe {
                buf = refmut.align_to_mut::<u8>().1;
            }
            if step == ELEMENT_SIZE {
                // Single stable read, can't exceed 4GiB WASM memory
                let src = operation
                    .address
                    .unwrap_or_else(|| rand(0, MEMORY_SIZE as u64 - len));
                assert!(src + len <= MEMORY_SIZE as u64);
                // Always use the first part of `MEMORY` to minimize the number of different
                // pages touched. This should in turn minimize the overhead of wasm
                // memory operations when testing out stable memory operations.
                stable::stable64_read(buf, src, len);

                for i in (0..len).step_by(step) {
                    // Reading u64 and u8 gives the same result on little endian system,
                    // provided the rest of the bytes are zeros.
                    // So the sum should match the sum of normal `read()`
                    let value = buf[i as usize];
                    if let Some(expected_value) = operation.value {
                        if expected_value != value {
                            trap_with(&format!(
                                "Value mismatch at {}, expected {}, got {}",
                                i, expected_value, value
                            ));
                        }
                    }
                    sum += value as u64;
                }
            } else {
                // Sparse stable reads, can address more than 4GiB
                let src = operation
                    .address
                    .unwrap_or_else(|| rand(0, STABLE_MEMORY_SIZE - len));
                assert!(src + len <= STABLE_MEMORY_SIZE);
                for i in (src..src + len).step_by(step) {
                    stable::stable64_read(buf, i, 1);
                    let value = buf[0];
                    if let Some(expected_value) = operation.value {
                        if expected_value != value {
                            trap_with(&format!(
                                "Value mismatch at {}, expected {}, got {}",
                                i, expected_value, value
                            ));
                        }
                    }
                    sum += value as u64;
                }
            }
        });
    }

    api::reply(sum.to_string().as_bytes());
}

/// Writes 8-byte values into the given stable memory region.
///
/// # Arguments
///
/// * `operation.repeat` - optional number of iterations (1 by default).
/// * `operation.address` - optional start address of the memory region (random by default).
/// * `operation.size` - size of the memory region in bytes.
/// * `operation.step` - optional interval between writes in bytes (contig. by default).
/// * `operation.value` - optional value to write (random by default)
fn stable_write() {
    let operation = operation_from_args();

    let repeat = operation.repeat.unwrap_or(1);
    let step = operation.step.unwrap_or(ELEMENT_SIZE);
    let value = operation.value.unwrap_or_else(|| rand(0, u8::MAX));
    let len = operation.size;
    for _ in 0..repeat {
        MEMORY.with(|memory| {
            let mut refmut = memory.borrow_mut();
            #[allow(unused_assignments)]
            let mut buf = vec![].as_mut_slice();
            unsafe {
                buf = refmut.align_to_mut::<u8>().1;
            }
            if step == ELEMENT_SIZE {
                // Single stable write, can't exceed 4GiB WASM memory
                let dst = operation
                    .address
                    .unwrap_or_else(|| rand(0, MEMORY_SIZE as u64 - len));
                assert!(dst + len <= MEMORY_SIZE as u64);
                // Always use the first part of `MEMORY` to minimize the number of different
                // pages touched. This should in turn minimize the overhead of wasm
                // memory operations when testing out stable memory operations.
                for i in (0..len).step_by(step) {
                    // Writing u64 and u8 gives the same result on little endian system,
                    // provided the rest of the bytes are zeros.
                    // So the sum should match the sum of normal `read()`
                    buf[i as usize] = value;
                }
                stable::stable64_write(dst, &buf[..len as usize]);
            } else {
                // Sparse stable write, can address more than 4GiB
                let dst = operation
                    .address
                    .unwrap_or_else(|| rand(0, STABLE_MEMORY_SIZE - len));
                assert!(dst + len <= STABLE_MEMORY_SIZE);
                for i in (dst..dst + len).step_by(step) {
                    buf[0] = value;
                    stable::stable64_write(i, &buf[..1]);
                }
            }
        });
    }

    api::reply(&[]);
}

/// Combines the read and write operations above.
///
/// # Arguments:
///
/// * `operation.repeat` - optional number of iterations (1 by default).
/// * `operation.address` - optional start address of the memory region (random by default).
/// * `operation.size` - size of the memory region in bytes.
/// * `operation.step` - optional interval between writes in bytes (contig. by default).
/// * `operation.value` - optional value to write (random by default)
fn stable_read_write() {
    let operation = operation_from_args();
    let mut sum = 0;

    let repeat = operation.repeat.unwrap_or(1);
    let step = operation.step.unwrap_or(ELEMENT_SIZE);
    let value = operation.value.unwrap_or_else(|| rand(0, u8::MAX));
    let len = operation.size;
    for _ in 0..repeat {
        MEMORY.with(|memory| {
            let mut refmut = memory.borrow_mut();
            #[allow(unused_assignments)]
            let mut buf = vec![].as_mut_slice();
            unsafe {
                buf = refmut.align_to_mut::<u8>().1;
            }
            if step == ELEMENT_SIZE {
                // Single stable read/write, can't exceed 4GiB WASM memory
                let dst = operation
                    .address
                    .unwrap_or_else(|| rand(0, MEMORY_SIZE as u64 - len));
                assert!(dst + len <= MEMORY_SIZE as u64);
                stable::stable64_read(buf, dst, len);
                // Always use first part of `MEMORY` to minimize the number of different pages
                // touched. This should in turn minimize the overhead of wasm memory
                // operations when testing out stable memory operations.
                for i in (0..len).step_by(step) {
                    sum += buf[i as usize] as u64;
                    buf[i as usize] = value;
                }
                stable::stable64_write(dst, &buf[..len as usize]);
            } else {
                // Sparse stable read/write, can address more than 4GiB
                let dst = operation
                    .address
                    .unwrap_or_else(|| rand(0, STABLE_MEMORY_SIZE - len));
                assert!(dst + len <= STABLE_MEMORY_SIZE);
                for i in (dst..dst + len).step_by(step) {
                    stable::stable64_read(buf, i, 1);
                    sum += buf[0] as u64;
                    buf[0] = value;
                    stable::stable64_write(i, &buf[..1]);
                }
            }
        });
    }

    api::reply(sum.to_string().as_bytes());
}

/// Copies a memory regions of the given size from one random address to another.
///
/// The copy always adds the given or a random value to each destination 8-byte word.
/// This is done to ensure that the memory regions remain different so
/// that multiple update calls get similar state.
///
/// The addresses are chosen such that they do not overlap.
///
/// # Arguments:
///
/// * `operation.repeat` - optional number of iterations (1 by default).
/// * `operation.size` - size of the memory region in bytes (must be <= MEMORY_SIZE / 2).
/// * `operation.step` - optional interval between writes in bytes (contig. by default).
/// * `operation.value` - optional value to add (random by default)
fn copy() {
    let operation = operation_from_args();

    let repeat = operation.repeat.unwrap_or(1);
    let step = operation.step.unwrap_or(ELEMENT_SIZE) / ELEMENT_SIZE;
    let value = operation.value.unwrap_or_else(|| rand(0, u8::MAX));
    // Address can't exceed 4GiB WASM memory
    let len = (operation.size as usize + ELEMENT_SIZE - 1) / ELEMENT_SIZE;
    assert!(2 * len <= MEMORY_LEN);
    MEMORY.with(|memory| {
        let mut memory_ref = memory.borrow_mut();
        let memory = memory_ref.as_mut_slice();
        for _ in 0..repeat {
            let src = rand(len, MEMORY_LEN - len + 1);
            let dst = rand(0, src - len + 1);
            for i in (0..len).step_by(step) {
                memory[dst + i] = memory[src + i] + value as u64;
            }
        }
    });
    api::reply(&[]);
}

#[export_name = "canister_update update_copy"]
fn update_copy() {
    copy();
}

#[export_name = "canister_update update_read"]
fn update_read() {
    read();
}

#[export_name = "canister_update update_read_write"]
fn update_read_write() {
    read_write();
}

#[export_name = "canister_update update_write"]
fn update_write() {
    write();
}

#[export_name = "canister_update update_stable_read"]
fn update_stable_read() {
    stable_read();
}

#[export_name = "canister_update update_stable_write"]
fn update_stable_write() {
    stable_write();
}

#[export_name = "canister_update update_stable_read_write"]
fn update_stable_read_write() {
    stable_read_write();
}

#[export_name = "canister_query query_copy"]
fn query_copy() {
    copy();
}

#[export_name = "canister_query query_read"]
fn query_read() {
    read();
}

#[export_name = "canister_query query_read_write"]
fn query_read_write() {
    read_write();
}

#[export_name = "canister_query query_write"]
fn query_write() {
    write();
}

#[export_name = "canister_query query_stable_read"]
fn query_stable_read() {
    stable_read();
}

#[export_name = "canister_query query_stable_write"]
fn query_stable_write() {
    stable_write();
}

#[export_name = "canister_query query_stable_read_write"]
fn query_stable_read_write() {
    stable_read_write();
}

#[export_name = "canister_init"]
fn main() {
    let mut memory = vec![0; MEMORY_LEN];
    // Ensure that all pages are different.
    let mut middle_of_page = PAGE_SIZE / ELEMENT_SIZE / 2;
    while (middle_of_page) < memory.len() {
        memory[middle_of_page] = middle_of_page as u64;
        middle_of_page += PAGE_SIZE
    }
    MEMORY.with(|s| s.replace(memory));
    api::print(format!(
        "Successfully initialized canister with {} bytes",
        MEMORY_SIZE,
    ));

    // Grow stable memory by `STABLE_MEMORY_SIZE`.
    if stable::stable64_grow(STABLE_MEMORY_SIZE / WASM_PAGE_SIZE_IN_BYTES as u64) == -1 {
        api::trap_with(&format!(
            "Could not grow stable memory by {} bytes",
            STABLE_MEMORY_SIZE,
        ));
    }

    api::print(format!(
        "Successfully initialized canister with {} bytes of stable memory",
        STABLE_MEMORY_SIZE,
    ));
}
