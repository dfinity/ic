use std::time::Duration;

use anyhow::Result;
use ic_crypto_sha2::Sha256;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_utils::interfaces::ManagementCanister;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(large_zipped_wasm))
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

/// Build a gzip stream made of DEFLATE stored blocks that decompresses
/// to the 8-byte empty WebAssembly module `\0asm\x01\x00\x00\x00`.
///
/// The first `blocks - 1` blocks are empty non-final stored blocks and the last
/// is a final stored block carrying the wasm payload, wrapped in a gzip header/trailer.
///
/// Each empty block adds one stack frame to libflate's recursive block decoder,
/// so large `blocks` counts produce the stack-overflow payload while decompressing
/// to identical bytes.
pub fn make_large_deflate_stream(blocks: usize) -> Vec<u8> {
    /// The minimal valid WebAssembly module.
    const WASM: [u8; 8] = [0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];
    /// Gzip header. CM=deflate, OS=unknown.
    const HEADER: [u8; 10] = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
    /// A non-final DEFLATE stored block of length zero: BFINAL=0, LEN=0, NLEN=0xffff.
    const EMPTY_NONFINAL_STORED_BLOCK: [u8; 5] = [0x00, 0x00, 0x00, 0xff, 0xff];
    /// Compute the IEEE CRC-32 (as used by gzip) of `data`.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xffff_ffff;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        !crc
    }

    let len = WASM.len() as u16;
    let mut payload =
        Vec::with_capacity(HEADER.len() + (blocks - 1) * EMPTY_NONFINAL_STORED_BLOCK.len() + 21);
    payload.extend_from_slice(&HEADER);
    for _ in 0..(blocks - 1) {
        payload.extend_from_slice(&EMPTY_NONFINAL_STORED_BLOCK);
    }
    // Final stored block: BFINAL byte, then LEN and its ones-complement NLEN
    // then the raw stored bytes.
    payload.push(1);
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(&(!len).to_le_bytes());
    payload.extend_from_slice(&WASM);
    // gzip trailer: CRC32 of the uncompressed data, then ISIZE mod 2^32.
    payload.extend_from_slice(&crc32(&WASM).to_le_bytes());
    payload.extend_from_slice(&(WASM.len() as u32).to_le_bytes());
    payload
}

pub fn large_zipped_wasm(env: TestEnv) {
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on(async move {
        let mgr = ManagementCanister::create(&agent);

        let canister_id = mgr
            .create_canister()
            .as_provisional_create_with_amount(None)
            .with_effective_canister_id(node.effective_canister_id())
            .call_and_wait()
            .await
            .expect("Couldn't create canister with provisional API.")
            .0;

        let compressed_wasm = make_large_deflate_stream(250000);
        let compressed_hash = Sha256::hash(&compressed_wasm);

        // this causes a crashloop if libflate.patch is not applied.
        let _ = mgr
            .install_code(&canister_id, &compressed_wasm)
            .call_and_wait()
            .await;
        // .expect("Couldn't install gzipped wasm");

        // wait to give the node some time to restart if it crashed (so the systest shows the assert_no_metrics_error).
        std::thread::sleep(Duration::from_secs(30));

        let canister_status = mgr
            .canister_status(&canister_id)
            .as_update()
            .call()
            .await
            .unwrap()
            .0;

        assert_eq!(canister_status.module_hash, Some(compressed_hash.to_vec()));
    })
}
