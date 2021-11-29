#![no_main]
use dfn_core::api::{arg_data, print, reply};
use std::ptr;

fn parse_u32_from_str_or_default(arg: &str, default: u32) -> u32 {
    if arg.starts_with("0x") {
        let s_no_prefix = arg.trim_start_matches("0x");
        return u32::from_str_radix(s_no_prefix, 16).unwrap_or(default);
    } else if arg.starts_with("0o") {
        let s_no_prefix = arg.trim_start_matches("0o");
        return u32::from_str_radix(s_no_prefix, 8).unwrap_or(default);
    } else if arg.starts_with("0b") {
        let s_no_prefix = arg.trim_start_matches("0b");
        return u32::from_str_radix(s_no_prefix, 2).unwrap_or(default);
    } else {
        return u32::from_str_radix(&arg, 10).unwrap_or(default);
    }
}

fn parse_args_start_end_iter() -> (u32, u32, u32) {
    let arg = &arg_data();
    let arg_str = String::from_utf8_lossy(arg);
    let arg_split = arg_str.split(' ').collect::<Vec<&str>>();

    let addr_start = if let Some(s) = arg_split.get(0) {
        parse_u32_from_str_or_default(s, 0)
    } else {
        0
    };

    let addr_end = if let Some(s) = arg_split.get(1) {
        parse_u32_from_str_or_default(s, 2 ^ 32 - 16)
    } else {
        2 ^ 32 - 16
    };

    let iter = if let Some(s) = arg_split.get(2) {
        parse_u32_from_str_or_default(s, 1)
    } else {
        1
    };

    (addr_start, addr_end, iter)
}

#[export_name = "canister_update benchmark_seq_read"]
fn seq_read() {
    let (addr_start, addr_end, iter) = parse_args_start_end_iter();

    print(&format!(
        "parsed_args ==> {} .. {}, {} iteration(s)",
        addr_start, addr_end, iter
    ));

    // current API requires us to specify size and alignment manually.
    let mut _v = Vec::<u8>::with_capacity((addr_end - addr_start) as usize);
    let mut sum: u64 = 0;
    for _i in 0..iter {
        for addr in (addr_start..addr_end).step_by(4) {
            let p = addr as *const u32;
            let val = unsafe { ptr::read(p) };
            sum += val as u64;
            // print(&format!("address {} ==> value {}", addr, val));
        }
    }

    print(&format!("all done! sum={}", sum));
    reply(b"success");
}

#[export_name = "canister_update benchmark_seq_write"]
fn seq_write() {
    let (addr_start, addr_end, iter) = parse_args_start_end_iter();

    print(&format!(
        "parsed_args ==> {} .. {}, {} iteration(s)",
        addr_start, addr_end, iter
    ));

    // Creating a vector with default value does a memory allocation
    // plus a write to that memory location, which is exactly what we want
    // for a sequential memory write
    for i in 0..iter as u8 {
        let _vec = vec![i; (addr_end - addr_start) as usize];
    }

    print(&format!("all done!"));
    reply(b"success");
}
