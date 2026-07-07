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
    let fixed_bytes = ic_cketh_minter::eth_logs::principal_to_bytes32(&principal);
    println!("0x{}", hex::encode(fixed_bytes));
}
