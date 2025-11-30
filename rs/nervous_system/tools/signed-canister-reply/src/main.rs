use clap::Parser;
use ic_nervous_system_signed_canister_reply::Argv;
use std::io::stdout;

#[tokio::main]
async fn main() {
    let stdout = stdout();
    let mut stdout = stdout.lock();

    Argv::parse().execute(&mut stdout).await;
}
