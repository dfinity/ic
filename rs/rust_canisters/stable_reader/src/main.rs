/// A tiny utility that takes a stable memory that was written by a canister
/// using this library on stdin and outputs the "actual" content (that is,
/// without the padding to an integer number of wasm pages) to stdout.
///
/// Example command line:
/// ```
/// cargo run --bin stable_reader -- < /tmp/.tmpoAVr5a/node-100/state/tip/canister_states/00000000000000010101/stable_memory.bin > ~/stable_memory_content.bin
/// ```
fn main() {
    match stable_reader::read(&mut std::io::stdin(), std::io::stdout()) {
        Ok(num_bytes) => eprintln!("Forwarded {} bytes to stdout.", num_bytes),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(-1);
        }
    }
}
