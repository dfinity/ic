//! This canister tests `BufferedStableMemWriter` and `BufferedStableMemReader`

use dfn_candid::candid;
use dfn_core::{over, println, stable};
use ic_nervous_system_common::dfn_core_stable_mem_utils::{
    BufferedStableMemReader, BufferedStableMemWriter,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_gtc::pb::v1::{AccountState, Gtc};
use prost::Message;
use std::ptr::addr_of_mut;

const LOG_PREFIX: &str = "[Gtc mem utils test] ";

#[cfg(target_arch = "wasm32")]
const WASM_PAGE_SIZE_BYTES: usize = 65536;

static mut GTC: Option<Gtc> = None;

#[unsafe(export_name = "canister_update test_empty")]
fn test_empty() {
    over(candid, |()| {
        println!("{}Testing empty serialization...", LOG_PREFIX);

        let mut writer = BufferedStableMemWriter::new(1024);
        writer.flush();

        assert_eq!(stable::length(), 0);
    })
}

#[unsafe(export_name = "canister_update test_buffer_size")]
fn test_buffer_size() {
    over(candid, |(buffer_size,): (u32,)| {
        println!("{}Testing with buffer size {}...", LOG_PREFIX, buffer_size);

        let gtc_opt = unsafe { &mut *addr_of_mut!(GTC) };
        let gtc = gtc_opt.as_mut().unwrap();

        // Make one of the vec fields larger then the buffer size, to test that
        // we can serialize bytes/string fields larger than the buffer size
        gtc.accounts.get_mut("0").unwrap().neuron_ids =
            vec![NeuronId::from_u64(1); buffer_size as usize / 4];

        let mut writer = BufferedStableMemWriter::new(buffer_size);
        gtc.encode(&mut writer).unwrap();
        writer.flush();

        // Check writer correctness
        let serialized = stable::get();
        let decoded = Gtc::decode(serialized.as_slice()).unwrap();

        assert_eq!(gtc, &decoded);

        // Check reader correctness
        let reader = BufferedStableMemReader::new(buffer_size);
        let decoded = Gtc::decode(reader).unwrap();

        assert_eq!(gtc, &decoded);
    })
}

#[unsafe(export_name = "canister_update test_1_byte_buffer")]
fn test_1_byte_buffer() {
    over(candid, |()| {
        println!("{}Testing small data with buffer size 1...", LOG_PREFIX);

        // Just a 1KiB data
        let mut data = Gtc::default();

        for i in 1..100 {
            data.accounts.insert(i.to_string(), AccountState::default());
        }

        {
            let mut serialized = vec![];
            data.encode(&mut serialized).unwrap();
            println!("{}Size of data = {}", LOG_PREFIX, serialized.len());
        }

        let mut writer = BufferedStableMemWriter::new(1);
        data.encode(&mut writer).unwrap();
        writer.flush();

        // Check writer correctness
        let serialized = stable::get();
        let decoded = Gtc::decode(serialized.as_slice()).unwrap();

        assert_eq!(data, decoded);

        // Check reader correctness
        let reader = BufferedStableMemReader::new(1);
        let decoded = Gtc::decode(reader).unwrap();

        assert_eq!(data, decoded);
    })
}

#[unsafe(export_name = "canister_init")]
fn canister_init() {
    dfn_core::printer::hook();

    let gtc = unsafe { &mut *addr_of_mut!(GTC) };

    #[cfg(target_arch = "wasm32")]
    let wasm_pages_init = core::arch::wasm32::memory_size(0);

    *gtc = Some(Gtc::default());

    let accounts = &mut gtc.as_mut().unwrap().accounts;

    for i in 0..200000 {
        accounts.insert(i.to_string(), AccountState::default());
    }

    #[cfg(target_arch = "wasm32")]
    {
        let wasm_pages_after_accounts = core::arch::wasm32::memory_size(0);
        println!(
            "{}In-memory size of data: ~{} bytes",
            LOG_PREFIX,
            (wasm_pages_after_accounts - wasm_pages_init) * WASM_PAGE_SIZE_BYTES
        );

        let mut serialized = Vec::new();
        gtc.as_ref().unwrap().encode(&mut serialized).unwrap();

        println!(
            "{}Size of serialization: {} bytes",
            LOG_PREFIX,
            serialized.len(),
        );
    }
}

fn main() {}
