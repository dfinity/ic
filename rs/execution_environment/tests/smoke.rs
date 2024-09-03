use candid::{decode_one, encode_args, CandidType};
use ic_management_canister_types::{EmptyBlob, Payload};
use ic_state_machine_tests::{StateMachine, WasmResult};
use serde::Deserialize;

// https://github.com/dfinity/motoko/blob/master/test/perf/qr.mo
const QR: &[u8] = include_bytes!("test-data/qr.wasm");

// https://github.com/crusso/motoko-gc-limits#scalability-suite
const COMPACTING_GC: &[u8] = include_bytes!("test-data/compacting-gc.wasm.gz");
const COPYING_GC: &[u8] = include_bytes!("test-data/copying-gc.wasm.gz");

// https://github.com/dfinity/motoko/blob/master/test/perf/sha256.mo
const SHA256: &[u8] = include_bytes!("test-data/sha256.wasm");

// https://github.com/dfinity/examples/tree/master/rust/image-classification
const IMAGE_CLASSIFICATION: &[u8] = include_bytes!("test-data/image-classification.wasm.gz");

#[test]
fn qr() {
    let env = StateMachine::new();
    let arg = encode_args(()).unwrap();
    let qr = env
        .install_canister(QR.to_vec(), arg.clone(), None)
        .unwrap();
    let reply = env.execute_ingress(qr, "go", arg).unwrap();
    assert_eq!(reply, WasmResult::Reply(EmptyBlob.encode()));
}

#[test]
fn compacting_gc() {
    let env = StateMachine::new();
    let compacting_gc = env
        .install_canister(COMPACTING_GC.to_vec(), encode_args(()).unwrap(), None)
        .unwrap();
    let arg = vec![
        0x44, 0x49, 0x44, 0x4c, 0x01, 0x6b, 0x01, 0xfb, 0x91, 0xc0, 0x43, 0x7f, 0x02, 0x7d, 0x00,
        0x80, 0x10, 0x00,
    ];
    let reply = env.execute_ingress(compacting_gc, "step", arg).unwrap();
    assert_eq!(reply, WasmResult::Reply(EmptyBlob.encode()));
}

#[test]
fn copying_gc() {
    let env = StateMachine::new();
    let copying_gc = env
        .install_canister(COPYING_GC.to_vec(), encode_args(()).unwrap(), None)
        .unwrap();
    let arg = vec![
        0x44, 0x49, 0x44, 0x4c, 0x01, 0x6b, 0x01, 0xfb, 0x91, 0xc0, 0x43, 0x7f, 0x02, 0x7d, 0x00,
        0x80, 0x10, 0x00,
    ];
    let reply = env.execute_ingress(copying_gc, "step", arg).unwrap();
    assert_eq!(reply, WasmResult::Reply(EmptyBlob.encode()));
}

#[test]
fn sha256() {
    let env = StateMachine::new();
    let sha256 = env
        .install_canister(SHA256.to_vec(), encode_args(()).unwrap(), None)
        .unwrap();
    let reply = env
        .execute_ingress(sha256, "go", encode_args(()).unwrap())
        .unwrap();
    assert_eq!(reply, WasmResult::Reply(EmptyBlob.encode()));
}

#[derive(PartialEq, Debug, CandidType, Deserialize)]
struct Classification {
    label: String,
    score: f32,
}

#[derive(PartialEq, Debug, CandidType, Deserialize)]
struct ClassificationError {
    message: String,
}

#[derive(PartialEq, Debug, CandidType, Deserialize)]
enum ClassificationResult {
    Ok(Vec<Classification>),
    Err(ClassificationError),
}

#[test]
fn image_classification() {
    let env = StateMachine::new();
    let image_classification = env
        .install_canister(
            IMAGE_CLASSIFICATION.to_vec(),
            encode_args(()).unwrap(),
            None,
        )
        .unwrap();
    let reply = env
        .execute_ingress(image_classification, "run", encode_args(()).unwrap())
        .unwrap();
    match reply {
        WasmResult::Reply(data) => {
            let res: ClassificationResult = decode_one(&data).unwrap();
            assert_eq!(
                res,
                ClassificationResult::Ok(vec![
                    Classification {
                        label: "tractor".to_string(),
                        score: 17.631065,
                    },
                    Classification {
                        label: "plow".to_string(),
                        score: 16.184143,
                    },
                    Classification {
                        label: "harvester".to_string(),
                        score: 14.577676,
                    }
                ])
            );
        }
        WasmResult::Reject(err) => unreachable!("Unexpected: {}", err),
    }
}
