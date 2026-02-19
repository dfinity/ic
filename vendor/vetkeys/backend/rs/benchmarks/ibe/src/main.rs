#[cfg(feature = "canbench-rs")]
mod benches {
    use canbench_rs::bench;
    use ic_vetkeys::*;

    fn setup_ibe(msg_size: usize) -> (IbeCiphertext, VetKey) {
        let tsk = TransportSecretKey::from_seed(vec![0x42; 32]).unwrap();

        let dpk = DerivedPublicKey::deserialize(&hex::decode("972c4c6cc184b56121a1d27ef1ca3a2334d1a51be93573bd18e168f78f8fe15ce44fb029ffe8e9c3ee6bea2660f4f35e0774a35a80d6236c050fd8f831475b5e145116d3e83d26c533545f64b08464e4bcc755f990a381efa89804212d4eef5f").unwrap()).unwrap();

        let ek = EncryptedVetKey::deserialize(&hex::decode("b1a13757eaae15a3c8884fc1a3453f8a29b88984418e65f1bd21042ce1d6809b2f8a49f7326c1327f2a3921e8ff1d6c3adde2a801f1f88de98ccb40c62e366a279e7aec5875a0ce2f2a9f3e109d9cb193f0197eadb2c5f5568ee4d6a87e115910662e01e604087246be8b081fc6b8a06b4b0100ed1935d8c8d18d9f70d61718c5dba23a641487e72b3b25884eeede8feb3c71599bfbcebe60d29408795c85b4bdf19588c034d898e7fc513be8dbd04cac702a1672f5625f5833d063b05df7503").unwrap()).unwrap();

        let identity = hex::decode("6d657373616765").unwrap();

        let msg = hex::decode("11".repeat(msg_size)).unwrap();
        let seed = IbeSeed::from_bytes(&[0u8; 32]).unwrap();
        let ctext = IbeCiphertext::encrypt(&dpk, &IbeIdentity::from_bytes(&identity), &msg, &seed);

        let vetkey = ek.decrypt_and_verify(&tsk, &dpk, &identity).unwrap();

        (ctext, vetkey)
    }

    #[bench(raw)]
    fn ibe_decrypt_32_bytes_msg() -> canbench_rs::BenchResult {
        // Prevent the compiler from optimizing the call and propagating constants.
        let (ctext, vetkey) = std::hint::black_box(setup_ibe(std::hint::black_box(32)));

        canbench_rs::bench_fn(move || {
            let _ptext = ctext.decrypt(&vetkey).expect("IBE decryption failed");
        })
    }

    #[bench(raw)]
    fn ibe_decrypt_1_000_bytes_msg() -> canbench_rs::BenchResult {
        // Prevent the compiler from optimizing the call and propagating constants.
        let (ctext, vetkey) = std::hint::black_box(setup_ibe(std::hint::black_box(1_000)));

        canbench_rs::bench_fn(move || {
            let _ptext = ctext.decrypt(&vetkey).expect("IBE decryption failed");
        })
    }

    #[bench(raw)]
    fn ibe_decrypt_100_000_bytes_msg() -> canbench_rs::BenchResult {
        // Prevent the compiler from optimizing the call and propagating constants.
        let (ctext, vetkey) = std::hint::black_box(setup_ibe(std::hint::black_box(100_000)));

        canbench_rs::bench_fn(move || {
            let _ptext = ctext.decrypt(&vetkey).expect("IBE decryption failed");
        })
    }

    #[bench(raw)]
    fn ibe_decrypt_2_000_000_bytes_msg() -> canbench_rs::BenchResult {
        // Prevent the compiler from optimizing the call and propagating constants.
        let (ctext, vetkey) = std::hint::black_box(setup_ibe(std::hint::black_box(2_000_000)));

        canbench_rs::bench_fn(move || {
            let _ptext = ctext.decrypt(&vetkey).expect("IBE decryption failed");
        })
    }
}

fn main() {}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of some other dependencies) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// the used RNGs are _manually_ seeded rather than by the system.
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
getrandom::register_custom_getrandom!(always_fail);
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
