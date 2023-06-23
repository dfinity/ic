//! This binary writes the lifeline canister Wasm to stdout so that the CI could publish it as an
//! artifact.

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!(
            "Expected exactly one argument (the name of the output file), got: {:?}",
            args
        );
        std::process::exit(1);
    }
    std::fs::write(&args[1], lifeline::LIFELINE_CANISTER_WASM)
        .unwrap_or_else(|e| panic!("failed to write Wasm to {}: {}", args[1], e));
}
