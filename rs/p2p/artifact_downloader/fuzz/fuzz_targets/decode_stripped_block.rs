#![no_main]
use ic_artifact_downloader::fetch_stripped_artifact::types::stripped::MaybeStrippedConsensusMessage;
use ic_protobuf::proxy::ProtoProxy;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::types::v1 as pb;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _res: Result<MaybeStrippedConsensusMessage, ProxyDecodeError> =
        pb::StrippedConsensusMessage::proxy_decode(&data);
});
