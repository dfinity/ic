use std::path::Path;

pub fn write(root: &Path, name: &str, wat: &str) {
    std::fs::write(
        root.join(name).into_os_string(),
        wat::parse_str(wat).unwrap(),
    )
    .unwrap();
}

pub fn write_bytes(root: &Path, name: &str, wasm: Vec<u8>) {
    std::fs::write(root.join(name).into_os_string(), wasm).unwrap();
}

pub fn write_end(root: &Path, name: &str, mut inner: Vec<String>) {
    let mut ret = vec!["(module\n".to_string()];
    ret.append(&mut inner);
    ret.push(end());
    std::fs::write(
        root.join(name).into_os_string(),
        wat::parse_str(ret.join("")).unwrap(),
    )
    .unwrap();
}

pub fn write_base_end(root: &Path, name: &str, mut inner: Vec<String>) {
    let mut ret = vec![base()];
    ret.append(&mut inner);
    ret.push(end());
    std::fs::write(
        root.join(name).into_os_string(),
        wat::parse_str(ret.join("")).unwrap(),
    )
    .unwrap();
}

pub fn add_exports(n: usize) -> Vec<String> {
    let mut ret = vec![];
    for i in 0..n {
        let t = if i % 3 == 0 {
            "update"
        } else if i % 3 == 1 {
            "query"
        } else {
            "composite_query"
        };
        ret.push(export(&format!("canister_{} m{}", t, i), "read"));
    }
    ret
}

pub fn export(name: &str, what: &str) -> String {
    format!("    (export \"{}\" (func ${}))\n", name, what)
}

pub fn add_long_exported_function_names(mut n: usize) -> Vec<String> {
    let mut ret = vec![];
    let a = n / 3;
    n -= a;
    let b = n / 2;
    n -= b;
    let c = n;
    ret.push(export(
        &format!(
            "canister_update {}",
            String::from_utf8(vec![b'a'; a]).unwrap()
        ),
        "read",
    ));
    ret.push(export(
        &format!(
            "canister_update {}",
            String::from_utf8(vec![b'b'; b]).unwrap()
        ),
        "read",
    ));
    ret.push(export(
        &format!(
            "canister_update {}",
            String::from_utf8(vec![b'c'; c]).unwrap()
        ),
        "read",
    ));
    ret
}

pub fn add_functions(n: usize) -> Vec<String> {
    let mut ret = vec![];
    for i in 0..n {
        ret.push(format!("    (func $m{})\n", i));
    }
    ret
}

pub fn add_globals(n: usize) -> Vec<String> {
    let mut ret = vec![];
    for i in 0..n {
        ret.push(format!("    (global i32 (i32.const {}))\n", i));
    }
    ret
}

pub fn enc32(x: usize) -> Vec<u8> {
    let mut buf = [0; 1024];
    let mut writable = &mut buf[..];
    let n =
        leb128::write::unsigned(&mut writable, x.try_into().unwrap()).expect("Should write number");
    buf[..n].to_vec()
}

pub fn add_custom_section(mut n: Vec<u8>, mut c: Vec<u8>) -> Vec<u8> {
    let mut ret = vec![0x00];
    ret.append(&mut enc32(enc32(n.len()).len() + n.len() + c.len()));
    ret.append(&mut enc32(n.len()));
    ret.append(&mut n);
    ret.append(&mut c);
    ret
}

pub fn with_custom_sections(cs: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let mut ret = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    for nc in cs {
        ret.append(&mut add_custom_section(nc.0, nc.1));
    }
    ret
}

pub fn base() -> String {
    r#"(module
    (import "ic0" "call_new"
        (func $ic0_call_new
            (param i32 i32)
            (param $method_name_src i32)    (param $method_name_len i32)
            (param $reply_fun i32)          (param $reply_env i32)
            (param $reject_fun i32)         (param $reject_env i32)
        ))
    (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
    (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
    (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
    (import "ic0" "msg_reply_data_append"
        (func $msg_reply_data_append (param i32 i32)))
    (import "ic0" "msg_reply" (func $msg_reply))
    (func $reta (result i32)
        (return (i32.const 42)))
    (func $retb (param $src i32))
    (func $inc
        (i32.store
            (i32.const 0)
            (i32.add (i32.load (i32.const 0)) (i32.const 4))))
    (func $read
        (call $msg_reply_data_append
            (i32.const 0)
            (i32.const 4))
        (call $msg_reply))
"#.to_string()
}

pub fn end() -> String {
    r#"(memory $memory 1)
)"#
    .to_string()
}

pub fn many_custom_sections(n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut cs = vec![];
    for i in 0..n {
        cs.push((
            format!(
                "icp:{} c{}",
                if i % 2 == 0 { "public" } else { "private" },
                i
            )
            .into_bytes(),
            format!("x{}", i).into_bytes(),
        ));
    }
    for i in 0..16 {
        cs.push((
            format!(
                "ic:{} c{}",
                if i % 2 == 0 { "public" } else { "private" },
                i
            )
            .into_bytes(),
            format!("x{}", i).into_bytes(),
        ));
    }
    cs
}

pub fn large_custom_sections(mut n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    n -= 2; // subtract the name lengths
    let a = n / 2;
    n -= a;
    let b = n;
    [
        (b"icp:private x".to_vec(), vec![b'a'; a]),
        (b"icp:public y".to_vec(), vec![b'b'; b]),
    ]
    .to_vec()
}
