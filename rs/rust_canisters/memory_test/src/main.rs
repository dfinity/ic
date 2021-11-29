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
const MEMORY_SIZE: usize = 1 << 30; // 1GiB.
const MEMORY_LEN: usize = MEMORY_SIZE / ELEMENT_SIZE;
const STABLE_MEMORY_SIZE: u64 = 6 * (1 << 30); // 6GiB.
const WASM_PAGE_SIZE_IN_BYTES: u64 = 64 * 1024; // 64 KiB

/// All methods get this struct as an argument encoded in a JSON string.
/// Each method performs some memory operation like `read`, `write`,
/// `read_write`, `copy` on some memory range. The address and the size
/// of the memory range is given in the corresponding fields. If the
/// address is omitted, then it is chosen randomly. The `value` field
/// specifies an 8 byte value to write or read. (Reading a value means
/// fetching the value from the memory and asserting that it is equal
/// to the given value). If the value is omitted, then a random value
/// is chosed for writing. Reading simply skips the comparison.
/// The `repeat` field specifies how many times to repeat the operation.
/// The default value is 1.
#[derive(Serialize, Deserialize, Debug)]
struct Operation {
    repeat: Option<usize>,
    address: Option<usize>,
    size: usize,
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
    static MEMORY: RefCell<Vec<u64>> = RefCell::new(vec![]);
}

fn arg_data() -> Vec<u8> {
    let len: u32 = unsafe { ic0::msg_arg_data_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::msg_arg_data_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    bytes
}

fn operation_from_args() -> Operation {
    let data = arg_data();
    match serde_json::from_slice(&data) {
        Ok(op) => op,
        Err(err) => {
            trap_with(&format!(
                "Failed to parse Operation from JSON.\nJSON: {}\nError: {:?}",
                String::from_utf8_lossy(&data),
                err,
            ));
            unreachable!("cannot reach here after the trap");
        }
    }
}

fn rand(low: usize, high: usize) -> usize {
    RNG.with(|rng| rng.borrow_mut().gen_range(low, high))
}

/// Reads and sums up all eight byte words in the given memory region.
///
/// Arguments:
/// - operation.repeat: the number of operations.
/// - operation.address: optional start address of the memory region. It is
///   chosen randomly if not given.
/// - operation.size: the size of the memory region in bytes.
/// - operation.value: optional eight byte value. If the value is given, then
///   the operation asserts that all read values match the given value.
fn read() {
    let operation = operation_from_args();
    let mut sum = 0;

    MEMORY.with(|memory| {
        let memory_ref = memory.borrow();
        let memory = memory_ref.as_slice();
        let repeat = operation.repeat.unwrap_or(1);
        let len = (operation.size + ELEMENT_SIZE - 1) / ELEMENT_SIZE;
        assert!(len <= MEMORY_LEN);
        for _ in 0..repeat {
            let src = operation
                .address
                .unwrap_or_else(|| rand(0, MEMORY_LEN - len + 1) * ELEMENT_SIZE)
                as usize
                / ELEMENT_SIZE;
            #[allow(clippy::needless_range_loop)]
            for i in src..src + len {
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

/// Writes the given eight byte value into the given memory region.
///
/// Arguments:
/// - operation.repeat: the number of operations.
/// - operation.address: optional start address of the memory region. It is
///   chosen randomly if not given.
/// - operation.size: the size of the memory region in bytes.
/// - operation.value: optional eight byte value. It is chosen randomly if not
///   given.
fn write() {
    let operation = operation_from_args();

    MEMORY.with(|memory| {
        let mut memory_ref = memory.borrow_mut();
        let memory = memory_ref.as_mut_slice();
        let repeat = operation.repeat.unwrap_or(1);
        let value = operation
            .value
            .unwrap_or_else(|| rand(0, u8::MAX.into()) as u8);
        let len = (operation.size + ELEMENT_SIZE - 1) / ELEMENT_SIZE;
        assert!(len <= MEMORY_LEN);
        for _ in 0..repeat {
            let dst = operation
                .address
                .unwrap_or_else(|| rand(0, MEMORY_LEN - len + 1) * ELEMENT_SIZE)
                / ELEMENT_SIZE;
            #[allow(clippy::needless_range_loop)]
            for i in dst..dst + len {
                memory[i] = value as u64;
            }
        }
    });
    api::reply(&[]);
}

/// Combines the read and write operations above.
///
/// Arguments:
/// - operation.repeat: the number of operations.
/// - operation.address: optional start address of the memory region. It is
///   chosen randomly if not given.
/// - operation.size: the size of the memory region in bytes.
/// - operation.value: optional eight byte value. It is chosen randomly if not
///   given.
fn read_write() {
    let operation = operation_from_args();
    let mut sum = 0;

    MEMORY.with(|memory| {
        let mut memory_ref = memory.borrow_mut();
        let memory = memory_ref.as_mut_slice();
        let repeat = operation.repeat.unwrap_or(1);
        let len = (operation.size + ELEMENT_SIZE - 1) / ELEMENT_SIZE;
        assert!(len <= MEMORY_LEN);
        let value = operation
            .value
            .unwrap_or_else(|| rand(0, u8::MAX.into()) as u8);
        for _ in 0..repeat {
            let src = operation
                .address
                .unwrap_or_else(|| rand(0, MEMORY_LEN - len + 1) * ELEMENT_SIZE)
                / ELEMENT_SIZE;
            #[allow(clippy::needless_range_loop)]
            for i in src..src + len {
                sum += memory[i];
                memory[i] = value as u64;
            }
        }
    });
    api::reply(sum.to_string().as_bytes());
}

/// Reads and sums up all byte words in the given stable memory region.
///
/// Arguments:
/// - operation.repeat: the number of operations.
/// - operation.address: optional start address of the stable memory region. It
///   is chosen randomly if not given.
/// - operation.size: the size of the stable memory region in bytes.
/// - operation.value: optional byte value. If the value is given, then the
///   operation asserts that all read values match the given value.
fn stable_read() {
    let operation = operation_from_args();
    let mut sum = 0;

    let repeat = operation.repeat.unwrap_or(1);
    let len = operation.size as u64;
    assert!(len <= STABLE_MEMORY_SIZE);
    for _ in 0..repeat {
        let dst = RNG.with(|rng| rng.borrow_mut().gen_range(0, STABLE_MEMORY_SIZE - len));
        MEMORY.with(|memory| {
            let mut refmut = memory.borrow_mut();
            #[allow(unused_assignments)]
            let mut buf = vec![].as_mut_slice();
            unsafe {
                buf = refmut.align_to_mut::<u8>().1;
            }
            // Always use the first part of `MEMORY` to minimize the number of different
            // pages touched. This should in turn minimize the overhead of wasm
            // memory operations when testing out stable memory operations.
            stable::stable64_read(buf, dst as u64, len as u64);
            #[allow(clippy::needless_range_loop)]
            for i in 0..len as usize {
                let value = buf[i];
                if let Some(expected_value) = operation.value {
                    if expected_value != value {
                        trap_with(&format!(
                            "Value mismatch at {}, expected {}, got {}",
                            i, expected_value, value
                        ));
                    }
                }
                sum += value;
            }
        });
    }

    api::reply(sum.to_string().as_bytes());
}

/// Writes the given byte value into the given stable memory region.
///
/// Arguments:
/// - operation.repeat: the number of operations.
/// - operation.address: optional start address of the stable memory region. It
///   is chosen randomly if not given.
/// - operation.size: the size of the stable memory region in bytes.
/// - operation.value: optional byte value. It is chosen randomly if not given.
fn stable_write() {
    let operation = operation_from_args();

    let repeat = operation.repeat.unwrap_or(1);
    let value = operation
        .value
        .unwrap_or_else(|| rand(0, u8::MAX.into()) as u8);
    let len = operation.size as u64;
    assert!(len <= STABLE_MEMORY_SIZE);
    for _ in 0..repeat {
        let dst = RNG.with(|rng| rng.borrow_mut().gen_range(0, STABLE_MEMORY_SIZE - len));
        MEMORY.with(|memory| {
            let mut refmut = memory.borrow_mut();
            #[allow(unused_assignments)]
            let mut buf = vec![].as_mut_slice();
            unsafe {
                buf = refmut.align_to_mut::<u8>().1;
            }
            // Always use the first part of `MEMORY` to minimize the number of different
            // pages touched. This should in turn minimize the overhead of wasm
            // memory operations when testing out stable memory operations.
            #[allow(clippy::needless_range_loop)]
            for i in 0..len as usize {
                buf[i] = value;
            }
            stable::stable64_write(dst as u64, &buf[..len as usize]);
        });
    }

    api::reply(&[]);
}

/// Combines the stable read and write operations above.
///
/// Arguments:
/// - operation.repeat: the number of operations.
/// - operation.address: optional start address of the stable memory region. It
///   is chosen randomly if not given.
/// - operation.size: the size of the stable memory region in bytes.
/// - operation.value: optional byte value. It is chosen randomly if not given.
fn stable_read_write() {
    let operation = operation_from_args();
    let mut sum = 0;

    let repeat = operation.repeat.unwrap_or(1);
    let value = operation
        .value
        .unwrap_or_else(|| rand(0, u8::MAX.into()) as u8);
    let len = operation.size as u64;
    assert!(len <= STABLE_MEMORY_SIZE);
    for _ in 0..repeat {
        let dst = RNG.with(|rng| rng.borrow_mut().gen_range(0, STABLE_MEMORY_SIZE - len));
        MEMORY.with(|memory| {
            let mut refmut = memory.borrow_mut();
            #[allow(unused_assignments)]
            let mut buf = vec![].as_mut_slice();
            unsafe {
                buf = refmut.align_to_mut::<u8>().1;
            }

            stable::stable64_read(buf, dst as u64, len as u64);
            #[allow(clippy::needless_range_loop)]
            for i in 0..len as usize {
                sum += buf[i];
            }

            // Always use first part of `MEMORY` to minimize the number of different pages
            // touched. This should in turn minimize the overhead of wasm memory
            // operations when testing out stable memory operations.
            #[allow(clippy::needless_range_loop)]
            for i in 0..len as usize {
                buf[i] = value;
            }
            stable::stable64_write(dst as u64, &buf[..len as usize]);
        });
    }

    api::reply(sum.to_string().as_bytes());
}

/// Copies a memory regions of the given size from one random address to another
/// and adds the given eight byte value to each destination eight byte word.
/// The latter is done to ensure that the memory regions remain different so
/// that multiple update calls get similar state.
///
/// The addresses are chosen such that they do not overlap.
///
/// Arguments:
/// - operation.repeat: the number of operations.
/// - operation.size: the size of the memory region in bytes. It must not exceed
///   MEMORY_SIZE / 2.
/// - operation.value: an optional value to be added on copy. It is chosen
///   randomly if not specified.
fn copy() {
    let operation = operation_from_args();
    MEMORY.with(|memory| {
        let mut memory_ref = memory.borrow_mut();
        let memory = memory_ref.as_mut_slice();
        let repeat = operation.repeat.unwrap_or(1);
        let len = (operation.size + ELEMENT_SIZE - 1) / ELEMENT_SIZE;
        assert!(2 * len <= MEMORY_LEN);
        let value = operation
            .value
            .unwrap_or_else(|| rand(0, u8::MAX.into()) as u8);
        for _ in 0..repeat {
            let src = rand(len, MEMORY_LEN - len + 1);
            let dst = rand(0, src - len + 1);
            for i in 0..len as usize {
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
    let mut memory = vec![0; MEMORY_LEN as usize];
    // Ensure that all pages are different.
    const PAGE_SIZE: usize = 4096;
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
    if stable::stable64_grow((STABLE_MEMORY_SIZE / WASM_PAGE_SIZE_IN_BYTES) as u64) == -1 {
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
