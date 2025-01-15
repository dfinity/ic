#![no_main]
use bitcoin::consensus::encode::deserialize;
use bitcoin::p2p::message::RawNetworkMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize::<RawNetworkMessage>(data);
});
