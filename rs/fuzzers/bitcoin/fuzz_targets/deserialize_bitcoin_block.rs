#![no_main]
use bitcoin::Block;
use bitcoin::consensus::encode::{deserialize, serialize};
use libfuzzer_sys::{Corpus, fuzz_target};

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
