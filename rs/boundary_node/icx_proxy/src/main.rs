// TODO: Remove after inspect_err stabilizes (rust-lang/rust#91345)
#![allow(unstable_name_collisions)]

use anyhow::Error;
use clap::Parser;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() -> Result<(), Error> {
    let opts = icx_proxy::Opts::parse();

    icx_proxy::main(opts)
}
