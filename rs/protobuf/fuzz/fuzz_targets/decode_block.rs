#![no_main]
use ic_protobuf::proxy::ProtoProxy;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::types::v1 as pb;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let decoded: Result<pb::Block, ProxyDecodeError> = pb::Block::proxy_decode(data);
    if let Ok(b) = decoded {
        let _d = ic_types::consensus::Block::try_from(b);
    }
});
