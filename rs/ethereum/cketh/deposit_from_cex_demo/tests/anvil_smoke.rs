use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A locally spawned `anvil` node, torn down on drop.
struct Anvil {
    child: Child,
    url: String,
}

impl Anvil {
    fn start() -> Self {
        let bin = std::env::var("ANVIL_BIN").expect("ANVIL_BIN not set by Bazel");
        // Let the OS hand us a free port, then release it for anvil to bind.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut child = Command::new(&bin)
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn anvil at {bin}: {e}"));
        let url = format!("http://127.0.0.1:{port}");
        wait_until_ready(&mut child, &bin, &url);
        Self { child, url }
    }

    fn rpc(&self, method: &str) -> serde_json::Value {
        let body: serde_json::Value = post_rpc(&self.url, method).unwrap().json().unwrap();
        body["result"].clone()
    }
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn post_rpc(url: &str, method: &str) -> reqwest::Result<reqwest::blocking::Response> {
    reqwest::blocking::Client::new()
        .post(url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": []
        }))
        .send()
}

fn wait_until_ready(child: &mut Child, bin: &str, url: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        // A wrong-arch or otherwise broken binary spawns but dies immediately;
        // surface that instead of polling a dead process until the timeout.
        if let Some(status) = child.try_wait().expect("failed to poll anvil") {
            panic!("anvil ({bin}) exited early with {status} before serving {url}");
        }
        if let Ok(resp) = post_rpc(url, "eth_blockNumber") {
            if resp.status().is_success() {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("anvil did not become ready within 30s at {url}");
}

#[test]
fn anvil_starts_and_serves_json_rpc() {
    let anvil = Anvil::start();

    // A fresh chain starts at block zero.
    assert_eq!(anvil.rpc("eth_blockNumber"), "0x0");

    // The node is reachable and reports a chain id.
    let chain_id = anvil.rpc("eth_chainId");
    assert!(chain_id.is_string(), "expected a chain id, got {chain_id}");
}
