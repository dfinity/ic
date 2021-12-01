use dfn_core::endpoint::{bytes, over};

#[export_name = "canister_query reverse"]
fn reverse() {
    over(bytes, |mut arg| {
        arg.reverse();
        arg
    })
}

#[export_name = "canister_query balance128"]
fn balance128() {
    over(bytes, |_| dfn_core::api::canister_cycle_balance128())
}

#[export_name = "canister_update set_certified_data"]
fn set_certified_data() {
    over(bytes, |bytes| {
        dfn_core::api::set_certified_data(&bytes[..]);
        bytes
    })
}

#[export_name = "canister_query get_certificate"]
fn get_certificate() {
    over(bytes, |_| dfn_core::api::data_certificate().unwrap())
}

#[export_name = "canister_update write_stable_memory_fn"]
fn write_stable_memory_fn() {
    over(bytes, |bytes| {
        dfn_core::stable::set(&bytes[..]);
        bytes
    })
}

#[export_name = "canister_update write_stable_memory_writer"]
fn write_stable_memory_writer() {
    over(bytes, |bytes| {
        use std::io::Write;
        let mut writer = dfn_core::stable::StableWriter::new();
        writer.write_all(&bytes).unwrap();
        writer.flush().unwrap();
        bytes
    })
}

#[export_name = "canister_query read_stable_memory_fn"]
fn read_stable_memory_fn() {
    over(bytes, |_| dfn_core::stable::get())
}

#[export_name = "canister_query read_stable_memory_reader"]
fn set_stable_memory_reader() {
    over(bytes, |_| {
        use std::io::Read;
        let mut reader = dfn_core::stable::StableReader::new();
        let mut buf = vec![];
        reader.read_to_end(&mut buf).unwrap();
        buf
    })
}

fn main() {}
