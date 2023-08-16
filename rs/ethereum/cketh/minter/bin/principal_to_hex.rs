use candid::Principal;
use std::str::FromStr;

fn usage() {
    eprintln!(
        "USAGE: {} PRINCIPAL",
        std::env::current_exe().unwrap().display()
    );
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        usage();
        std::process::exit(1);
    }
    let principal_text = &args[1];
    let principal = match Principal::from_str(principal_text) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("failed to parse principal from text {principal_text}: {msg}");
            std::process::exit(1)
        }
    };
    let n = principal.as_slice().len();
    assert!(n <= 29);
    let mut fixed_bytes = [0u8; 32];
    fixed_bytes[0] = n as u8;
    fixed_bytes[1..=n].copy_from_slice(principal.as_slice());
    println!("0x{}", hex::encode(fixed_bytes));
}
