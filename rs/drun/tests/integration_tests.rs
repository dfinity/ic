use std::io::{Read, Write};
use std::process::Command;
use tempfile::NamedTempFile;

const CANISTER_WAT: &str = r#"(module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reject" (func $msg_reject (param i32 i32)))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
        (import "ic0" "debug_print"
            (func $debug_print (param i32 i32)))
        (import "ic0" "stable_grow"
            (func $ic0_stable_grow (param $pages i32) (result i32)))
        (import "ic0" "stable_read"
            (func $ic0_stable_read (param $dst i32) (param $offset i32) (param $size i32)))
        (import "ic0" "stable_write"
            (func $ic0_stable_write (param $offset i32) (param $src i32) (param $size i32)))
        (func $init
            (drop (call $ic0_stable_grow (i32.const 1)))
            (i32.store (i32.const 0) (i32.const 1145258561))
            (call $debug_print
                (i32.const 0) ;; the counter from heap[0]
                (i32.const 4)) ;; length
            (call $msg_reply_data_append
                (i32.const 0) ;; the counter from heap[0]
                (i32.const 4)) ;; length
            (call $msg_reply))
        (func $rej
            (i32.store (i32.const 0) (i32.const 1145258561))
            (call $msg_reject (i32.const 0) (i32.const 4)))
        (func $inc
            (call $ic0_stable_read (i32.const 0) (i32.const 0) (i32.const 4))
            (i32.store
                (i32.const 0)
                (i32.add (i32.load (i32.const 0)) (i32.const 2)))
            (call $ic0_stable_write (i32.const 0) (i32.const 0) (i32.const 4))
            (call $msg_reply))
        (func $read
            (call $ic0_stable_read (i32.const 0) (i32.const 0) (i32.const 4))
            (call $msg_reply_data_append
                (i32.const 0) ;; the counter from heap[0]
                (i32.const 4)) ;; length
            (call $msg_reply))
        (memory $memory 1)
        (export "canister_query read" (func $read))
        (export "canister_update inc" (func $inc))
        (export "canister_update reject" (func $rej))
        (export "canister_update init" (func $init))
)"#;

fn messages(canister_file_path: &str) -> Vec<u8> {
    format!(
        r#"create
install lxzze-o7777-77777-aaaaa-cai {} ""
reinstall lxzze-o7777-77777-aaaaa-cai {} ""
upgrade lxzze-o7777-77777-aaaaa-cai {} ""
ingress lxzze-o7777-77777-aaaaa-cai init ""
ingress lxzze-o7777-77777-aaaaa-cai foo ""
query lxzze-o7777-77777-aaaaa-cai foo ""
ingress lxzze-o7777-77777-aaaaa-cai inc ""
ingress lxzze-o7777-77777-aaaaa-cai inc ""
ingress lxzze-o7777-77777-aaaaa-cai read ""
query lxzze-o7777-77777-aaaaa-cai read ""
ingress lxzze-o7777-77777-aaaaa-cai reject """#,
        canister_file_path, canister_file_path, canister_file_path,
    )
    .as_bytes()
    .to_vec()
}

fn expected_output() -> Vec<u8> {
    r#"Canister created: lxzze-o7777-77777-aaaaa-cai
Canister successfully installed.
Canister successfully installed.
Canister successfully installed.
2021-05-06 19:17:10.000000006 UTC: [Canister lxzze-o7777-77777-aaaaa-cai] ABCD
ingress Ok: Reply: 0x41424344
ingress Err: IC0536: Error from Canister lxzze-o7777-77777-aaaaa-cai: Canister has no update method 'foo'..
Check that the method being called is exported by the target canister. See documentation: http://internetcomputer.org/docs/current/references/execution-errors#method-not-found
Err: IC0536: Error from Canister lxzze-o7777-77777-aaaaa-cai: Canister has no query method 'foo'..
Check that the method being called is exported by the target canister. See documentation: http://internetcomputer.org/docs/current/references/execution-errors#method-not-found
ingress Ok: Reply: 0x
ingress Ok: Reply: 0x
ingress Ok: Reply: 0x04000000
Ok: Reply: 0x04000000
ingress Ok: Reject: ABCD
"#
    .as_bytes()
    .to_vec()
}

#[test]
fn end_to_end_test() {
    let mut canister_file = NamedTempFile::new().unwrap();
    let canister_wasm = wat::parse_str(CANISTER_WAT).unwrap();
    canister_file.write_all(&canister_wasm).unwrap();
    let canister_file_path = canister_file.path();

    let mut messages_file = NamedTempFile::new().unwrap();
    messages_file
        .write_all(&messages(canister_file_path.as_os_str().to_str().unwrap()))
        .unwrap();
    let messages_file_path = messages_file.path();

    let drun_path = std::env::var_os("DRUN_BIN").expect("Missing drun binary");
    let output = Command::new(drun_path)
        .arg(messages_file_path)
        .output()
        .expect("failed to execute process");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, expected_output());
}

#[test]
fn system_subnet() {
    let mut canister_file = NamedTempFile::new().unwrap();
    let canister_wasm = wat::parse_str(CANISTER_WAT).unwrap();
    canister_file.write_all(&canister_wasm).unwrap();
    let canister_file_path = canister_file.path();

    let mut messages_file = NamedTempFile::new().unwrap();
    messages_file
        .write_all(&messages(canister_file_path.as_os_str().to_str().unwrap()))
        .unwrap();
    let messages_file_path = messages_file.path();

    let drun_path = std::env::var_os("DRUN_BIN").expect("Missing drun binary");
    let output = Command::new(drun_path)
        .arg(messages_file_path)
        .arg("--subnet-type")
        .arg("system")
        .output()
        .expect("failed to execute process");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, expected_output());
}

#[test]
fn test_log_file() {
    let mut canister_file = NamedTempFile::new().unwrap();
    let canister_wasm = wat::parse_str(CANISTER_WAT).unwrap();
    canister_file.write_all(&canister_wasm).unwrap();
    let canister_file_path = canister_file.path();

    let mut messages_file = NamedTempFile::new().unwrap();
    messages_file
        .write_all(&messages(canister_file_path.as_os_str().to_str().unwrap()))
        .unwrap();
    let messages_file_path = messages_file.path();

    let mut log_file = NamedTempFile::new().unwrap();

    let drun_path = std::env::var_os("DRUN_BIN").expect("Missing drun binary");
    let output = Command::new(drun_path)
        .arg(messages_file_path)
        .arg("--log-file")
        .arg(log_file.path())
        .output()
        .expect("failed to execute process");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, expected_output());

    let mut buffer = String::new();
    log_file.read_to_string(&mut buffer).unwrap();
    assert!(buffer.contains("The PocketIC server is listening on port"));
    assert!(!buffer.contains("Canister lxzze-o7777-77777-aaaaa-cai"));
}

#[test]
fn test_cycles_used_file() {
    let mut canister_file = NamedTempFile::new().unwrap();
    let canister_wasm = wat::parse_str(CANISTER_WAT).unwrap();
    canister_file.write_all(&canister_wasm).unwrap();
    let canister_file_path = canister_file.path();

    let mut messages_file = NamedTempFile::new().unwrap();
    messages_file
        .write_all(&messages(canister_file_path.as_os_str().to_str().unwrap()))
        .unwrap();
    let messages_file_path = messages_file.path();

    let mut cycles_used_file = NamedTempFile::new().unwrap();

    let drun_path = std::env::var_os("DRUN_BIN").expect("Missing drun binary");
    let output = Command::new(drun_path)
        .arg(messages_file_path)
        .arg("--cycles-used-file")
        .arg(cycles_used_file.path())
        .output()
        .expect("failed to execute process");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, expected_output());

    let mut buffer = String::new();
    cycles_used_file.read_to_string(&mut buffer).unwrap();
    assert!(buffer.contains("lxzze-o7777-77777-aaaaa-cai:"));
}
