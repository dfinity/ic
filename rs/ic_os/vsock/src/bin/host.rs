use vsock_lib::server::run_server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    run_server().await
}
