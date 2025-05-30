#![no_main]
use ic_protobuf::proxy::ProtoProxy;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::types::v1 as pb;
use libfuzzer_sys::fuzz_target;
use pb::Block;

fuzz_target!(|data: &[u8]| {
    let _decoded: Result<Block, ProxyDecodeError> = pb::Block::proxy_decode(data);
});
