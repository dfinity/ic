use anyhow::{anyhow, Context, Result};
use ic_agent::agent::http_transport::reqwest_transport::ReqwestTransport;
use ic_agent::Agent;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use tokio::time::{sleep, Duration, Instant};

struct KillOnDrop(Child);

pub struct ReplicaContext {
    _proc: KillOnDrop,
    _state: tempfile::TempDir,
    pub port: u16,
}

impl ReplicaContext {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReplicaBins {
    pub canister_launcher: PathBuf,
    pub replica_bin: PathBuf,
    pub sandbox_launcher: PathBuf,
    pub starter_bin: PathBuf,
}

impl ReplicaBins {
    fn assert_bins_exist(&self) -> anyhow::Result<()> {
        for (bin, name) in [
            (&self.canister_launcher, "canister_launcher"),
            (&self.replica_bin, "replica_bin"),
            (&self.sandbox_launcher, "sandbox_launcher"),
            (&self.starter_bin, "starter_bin"),
        ] {
            if !bin.exists() {
                return Err(anyhow!("{} path {} does not exist", name, bin.display()));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReplicaStarterConfig {
    // The period since starting the replica after which
    // the [start_replica] method will return an error
    timeout_after: Duration,
}

impl Default for ReplicaStarterConfig {
    fn default() -> Self {
        Self {
            timeout_after: Duration::from_secs(25),
        }
    }
}

pub async fn start_replica(
    replica_bins: &ReplicaBins,
    config: &ReplicaStarterConfig,
) -> Result<ReplicaContext> {
    let state = tempfile::TempDir::new()?;

    let port_file = state.path().join("replica.port");

    replica_bins.assert_bins_exist()?;

    // replica expects canister_launcher and sandbox_launcher to the in the PATH
    let canister_launcher_parent = replica_bins
        .canister_launcher
        .parent()
        .ok_or_else(|| {
            anyhow!(
                "Unable to find the parent directory of canister_launcher {}",
                replica_bins.canister_launcher.display()
            )
        })?
        .to_str()
        .unwrap();
    let sandbox_launcher_parent = replica_bins
        .sandbox_launcher
        .parent()
        .ok_or_else(|| {
            anyhow!(
                "Unable to find the parent directory of sandbox_launcher {}",
                replica_bins.sandbox_launcher.display()
            )
        })?
        .to_str()
        .unwrap();
    let replica_path = format!(
        "{}:{}{}",
        canister_launcher_parent,
        sandbox_launcher_parent,
        std::env::var("PATH").map_or("".to_string(), |s| format!(":{}", s))
    );

    let mut cmd = Command::new(replica_bins.starter_bin.clone());
    cmd.env("RUST_MIN_STACK", "8192000")
        .env("PATH", replica_path)
        .arg("--replica-path")
        .arg(replica_bins.replica_bin.clone())
        .arg("--state-dir")
        .arg(state.path())
        .arg("--create-funds-whitelist")
        .arg("*")
        .arg("--log-level")
        .arg("critical")
        .arg("--subnet-type")
        .arg("system")
        .arg("--subnet-features")
        .arg("canister_sandboxing")
        .arg("--http-port-file")
        .arg(&port_file)
        .arg("--initial-notary-delay-millis")
        .arg("600");

    #[cfg(target_os = "macos")]
    cmd.args(["--consensus-pool-backend", "rocksdb"]);

    let _proc = KillOnDrop(
        cmd.stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .with_context(|| {
                anyhow!(
                    "Failed to execute ic-starter (path = {})",
                    replica_bins.starter_bin.display()
                )
            })?,
    );

    let start_time = Instant::now();
    while !port_file.exists() {
        sleep(Duration::from_millis(100)).await;
        if start_time + config.timeout_after <= Instant::now() {
            return Err(anyhow!(
                "replica didn't create port file {} within timeout of {:?}",
                port_file.display(),
                config.timeout_after
            ));
        }
    }

    let port_bytes = std::fs::read(&port_file)
        .with_context(|| anyhow!("failed to the ic-replica port file {}", port_file.display()))?;
    let contents = String::from_utf8(port_bytes).with_context(|| {
        anyhow!(
            "replica port file {} contains invalid UTF-8",
            port_file.display()
        )
    })?;

    let port: u16 = contents.parse().with_context(|| {
        anyhow!(
            "failed to parse ic-replica port file {} contents {}",
            port_file.display(),
            contents,
        )
    })?;

    let transport = Arc::new(
        ReqwestTransport::create(format!("http://localhost:{}", port))
            .context("failed to construct the replica transport")?,
    );

    let agent = Agent::builder()
        .with_transport(transport)
        .build()
        .context("failed to build agent")?;

    let start_time = Instant::now();
    let mut ok = false;
    let mut last_status = None;
    while !ok {
        match agent.status().await {
            Ok(status) => {
                ok = status.replica_health_status == Some("healthy".to_string());
                if let Some(root_key) = status.root_key.as_ref() {
                    agent.set_root_key(root_key.clone());
                }
                last_status = Some(status);
            }
            Err(_) => {
                sleep(Duration::from_millis(500)).await;
                if start_time + config.timeout_after <= Instant::now() {
                    break;
                }
            }
        }
    }

    if !ok {
        return Err(anyhow!(
            "Replica did not become healthy on port {}, status: {:?}",
            port,
            last_status
        ));
    }

    Ok(ReplicaContext {
        _proc,
        _state: state,
        port,
    })
}
