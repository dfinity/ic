#![no_main]
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::{deserialize, serialize};
use libfuzzer_sys::{Corpus, fuzz_target};

fuzz_target!(|data: &[u8]| -> Corpus {
    match deserialize::<Transaction>(data) {
        Ok(tx) => {
            let ser = serialize(&tx);
            assert_eq!(&ser[..], data);
            Corpus::Keep
        }
        Err(_) => Corpus::Reject,
    }
});
