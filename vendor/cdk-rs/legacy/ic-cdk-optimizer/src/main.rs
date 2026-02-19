use clap::Parser;
use humansize::{file_size_opts, FileSize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

mod passes;

#[derive(Parser, Debug)]
#[clap(version)]
struct CommandLineOpts {
    /// Input file to optimize. By default, or if "-", will use STDIN.
    #[clap(default_value("-"))]
    input: PathBuf,

    /// Output file. If unset, the original file will be overwritten. If "-", or if unset and the original was passed via STDIN, the result will go to STDOUT.
    #[clap(short, long)]
    output: Option<PathBuf>,
}

fn main() {
    let passes = passes::create();
    let opts = CommandLineOpts::parse();
    let content = if opts.input != Path::new("-") {
        std::fs::read(&opts.input).expect("Could not read the file.")
    } else {
        let mut buff = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buff)
            .expect("Could not read STDIN.");
        buff
    };

    eprintln!(
        "Original:          {:>8}",
        content.len().file_size(file_size_opts::BINARY).unwrap()
    );

    let original_wasm_size = content.len();
    let mut wasm_size = content.len();
    let mut wasm_back = content;

    for pass in passes {
        eprintln!("{}...", pass.description());
        let new_wasm = pass.opt(&wasm_back).expect("Pass failed:");
        if new_wasm.len() < wasm_back.len() {
            wasm_back = new_wasm;
            eprintln!(
                "    Size:          {:>8} ({:3.1}% smaller)",
                wasm_back.len().file_size(file_size_opts::BINARY).unwrap(),
                (1.0 - ((wasm_back.len() as f64) / (wasm_size as f64))) * 100.0
            );
        } else {
            eprintln!("Pass did not result in smaller WASM... Skipping.");
        }
        wasm_size = wasm_back.len();
    }

    eprintln!(
        "\nFinal Size: {} ({:3.1}% smaller)",
        wasm_back.len().file_size(file_size_opts::BINARY).unwrap(),
        (1.0 - ((wasm_back.len() as f64) / (original_wasm_size as f64))) * 100.0
    );
    let outfile = opts.output.unwrap_or(opts.input);
    if outfile == Path::new("-") {
        std::io::stdout()
            .write_all(&wasm_back)
            .expect("Could not write output.");
    } else {
        std::fs::write(outfile, wasm_back).expect("Could not write output file.");
    }
}
