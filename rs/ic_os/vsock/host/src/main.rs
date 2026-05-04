#![cfg(target_os = "linux")]

use vsock_lib::run_server;
fn main() -> std::io::Result<()> {
    run_server()
}
