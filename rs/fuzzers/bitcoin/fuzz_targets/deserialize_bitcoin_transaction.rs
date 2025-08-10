#![no_main]
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::{deserialize, serialize};
use libfuzzer_sys::{fuzz_target, Corpus};

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
