use ic_crypto::cli;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    cli::main(&args[1..])
        .map_err(|(message, code)| {
            eprintln!("{}", message);
            std::process::exit(code);
        })
        .expect("DIE");
}
