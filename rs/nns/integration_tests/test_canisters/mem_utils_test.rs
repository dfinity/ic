//! This canister tests `BufferedStableMemWriter` and `BufferedStableMemReader`

use dfn_candid::candid;
use dfn_core::{over, println, stable};

use ic_nervous_system_common::stable_mem_utils::{
    BufferedStableMemReader, BufferedStableMemWriter,
};
use ic_nns_governance::pb::v1::{Governance, Neuron};

use prost::Message;

const LOG_PREFIX: &str = "[Governance mem utils test] ";

#[cfg(target_arch = "wasm32")]
const WASM_PAGE_SIZE_BYTES: usize = 65536;

static mut GOVERNANCE: Option<Governance> = None;

#[export_name = "canister_update test_empty"]
fn test_empty() {
    over(candid, |()| {
        println!("{}Testing empty serialization...", LOG_PREFIX);

        let mut writer = BufferedStableMemWriter::new(1024);
        writer.flush();

        assert_eq!(stable::length(), 0);
    })
}

#[export_name = "canister_update test_buffer_size"]
fn test_buffer_size() {
    over(candid, |(buffer_size,): (u32,)| {
        println!("{}Testing with buffer size {}...", LOG_PREFIX, buffer_size);

        let gov_opt = unsafe { &mut GOVERNANCE };
        let gov = gov_opt.as_mut().unwrap();

        // Make one of the vec fields larger then the buffer size, to test that
        // we can serialize bytes/string fields larger than the buffer size
        gov.neurons.get_mut(&0).unwrap().account = vec![0; buffer_size as usize * 2];

        let mut writer = BufferedStableMemWriter::new(buffer_size);
        gov.encode(&mut writer).unwrap();
        writer.flush();

        // Check writer correctness
        let serialized = stable::get();
        let decoded = Governance::decode(serialized.as_slice()).unwrap();

        assert_eq!(gov, &decoded);

        // Check reader correctness
        let reader = BufferedStableMemReader::new(buffer_size);
        let decoded = Governance::decode(reader).unwrap();

        assert_eq!(gov, &decoded);
    })
}

#[export_name = "canister_update test_1_byte_buffer"]
fn test_1_byte_buffer() {
    over(candid, |()| {
        println!("{}Testing small data with buffer size 1...", LOG_PREFIX);

        // Just a 1KiB data
        let mut data = Governance::default();

        for i in 1..100 {
            data.neurons.insert(i, Neuron::default());
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
        let decoded = Governance::decode(serialized.as_slice()).unwrap();

        assert_eq!(data, decoded);

        // Check reader correctness
        let reader = BufferedStableMemReader::new(1);
        let decoded = Governance::decode(reader).unwrap();

        assert_eq!(data, decoded);
    })
}

#[export_name = "canister_init"]
fn canister_init() {
    dfn_core::printer::hook();

    let gov = unsafe { &mut GOVERNANCE };

    #[cfg(target_arch = "wasm32")]
    let wasm_pages_init = core::arch::wasm32::memory_size(0);

    *gov = Some(Governance::default());

    let neurons = &mut gov.as_mut().unwrap().neurons;

    for i in 0..200000 {
        neurons.insert(i, Neuron::default());
    }

    #[cfg(target_arch = "wasm32")]
    {
        let wasm_pages_after_neurons = core::arch::wasm32::memory_size(0);
        println!(
            "{}In-memory size of data: ~{} bytes",
            LOG_PREFIX,
            (wasm_pages_after_neurons - wasm_pages_init) * WASM_PAGE_SIZE_BYTES
        );

        let mut serialized = Vec::new();
        gov.as_ref().unwrap().encode(&mut serialized).unwrap();

        println!(
            "{}Size of serialization: {} bytes",
            LOG_PREFIX,
            serialized.len(),
        );
    }
}

fn main() {}
