#![no_main]
use libfuzzer_sys::fuzz_target;
use ic_protobuf::types::v1 as pb;

fuzz_target!(|data: &[u8]| {
    let _decoded = pb::Block::proxy_decode(&data);
}); 