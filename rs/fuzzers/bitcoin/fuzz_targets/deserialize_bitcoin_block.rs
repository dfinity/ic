#![no_main]
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::Block;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    match deserialize::<Block>(data) {
        Ok(block) => {
            let ser = serialize(&block);
            assert_eq!(&ser[..], data);
            Corpus::Keep
        }
        Err(_) => Corpus::Reject,
    }
});
