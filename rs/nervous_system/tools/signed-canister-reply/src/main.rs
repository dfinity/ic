use ic_nervous_system_signed_canister_reply::Argv;
use clap::Parser;
use std::io::stdout;

#[tokio::main]
async fn main() {
    let stdout = stdout();
    let mut stdout = stdout.lock();

    Argv::parse().execute(&mut stdout).await;
}
