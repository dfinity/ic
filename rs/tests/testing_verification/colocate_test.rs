use std::fs::File;
use std::io::{Read, Write};
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use std::time::Duration;
use std::{env, fs};

#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::constants::SSH_USERNAME;
use ic_tests::driver::driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR};
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::driver::test_env::{TestEnv, TestEnvAttribute};
use ic_tests::driver::test_env_api::{retry, FarmBaseUrl, HasDependencies, SshSession};
use ic_tests::driver::test_setup::GroupSetup;
use ic_tests::driver::universal_vm::{UniversalVm, UniversalVms};
use serde::Deserialize;
use slog::{error, info, warn};
use ssh2::Session;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpSocket;
use tokio::runtime::Runtime;

const UVM_NAME: &str = "test-driver";
const COLOCATED_TEST: &str = "COLOCATED_TEST";
const COLOCATED_TEST_BIN: &str = "COLOCATED_TEST_BIN";
const EXTRA_TIME_LOG_COLLECTION: Duration = Duration::from_secs(10);
const RETRY_LOG_READ_DELAY: Duration = Duration::from_secs(5);

pub const ENV_TAR_ZST: &str = "env.tar.zst";

pub const SCP_RETRY_TIMEOUT: Duration = Duration::from_secs(60);
pub const SCP_RETRY_BACKOFF: Duration = Duration::from_secs(5);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(3 * 60 * 60))
        .with_timeout_per_test(Duration::from_secs(3 * 60 * 60))
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

fn setup(env: TestEnv) {
    let colocated_test = env::var(COLOCATED_TEST)
        .unwrap_or_else(|_| panic!("Expected environment variable {COLOCATED_TEST} to be set!"));
    let colocated_test_bin = env::var(COLOCATED_TEST_BIN).unwrap_or_else(|_| {
        panic!("Expected environment variable {COLOCATED_TEST_BIN} to be set!")
    });
    let log = env.logger();

    info!(
        log,
        "Preparing Universal VM {UVM_NAME} which is going to run {colocated_test}..."
    );

    UniversalVm::new(UVM_NAME.to_string())
        .with_config_img(env.get_dependency_path("rs/tests/colocate_uvm_config_image.zst"))
        .start(&env)
        .unwrap_or_else(|e| panic!("Failed to setup Universal VM {UVM_NAME} because: {e}"));
    info!(log, "Universal VM {UVM_NAME} installed!");

    let ic_version_file = PathBuf::from(std::env::var("IC_VERSION_FILE").unwrap());

    let env_tar_path = env.get_path(ENV_TAR_ZST);
    info!(log, "Creating {env_tar_path:?} ...");
    let output = Command::new("tar")
        .arg("--create")
        .arg("--file")
        .arg(env_tar_path.clone())
        .arg("--auto-compress")
        .arg("--directory")
        .arg(env.base_path())
        .arg("--dereference")
        .arg("--exclude=dependencies/rs/tests/colocate_test_bin")
        .arg("--exclude=dependencies/rs/tests/colocate_uvm_config_image.zst")
        .arg("dependencies")
        .arg(Path::new(&FarmBaseUrl::attribute_name()).with_extension("json"))
        .arg(Path::new(&GroupSetup::attribute_name()).with_extension("json"))
        .arg(Path::new(SSH_AUTHORIZED_PUB_KEYS_DIR).join(SSH_USERNAME))
        .arg(Path::new(SSH_AUTHORIZED_PRIV_KEYS_DIR).join(SSH_USERNAME))
        .output()
        .unwrap_or_else(|e| panic!("Failed to tar the dependencies directory because: {e}"));

    if !output.status.success() {
        let err = str::from_utf8(&output.stderr).unwrap_or("");
        panic!("Tarring the dependencies directory failed with error: {err}");
    }

    let uvm = env.get_deployed_universal_vm(UVM_NAME).unwrap();

    info!(log, "Setting up SSH session to {UVM_NAME} UVM ...");
    let session = uvm
        .block_on_ssh_session()
        .unwrap_or_else(|e| panic!("Failed to setup SSH session to {UVM_NAME} because: {e}"));

    let size = fs::metadata(env_tar_path.clone()).unwrap().len();
    let to = Path::new("/home/admin").join(ENV_TAR_ZST);
    info!(
        log,
        "scp-ing {:?} of {:?} KiB to {UVM_NAME}:{to:?} ...",
        env_tar_path,
        size / 1024,
    );
    retry(env.logger(), SCP_RETRY_TIMEOUT, SCP_RETRY_BACKOFF, || {
        let mut remote_file = session.scp_send(&to, 0o644, size, None)?;
        let mut from_file = File::open(env_tar_path.clone())?;
        std::io::copy(&mut from_file, &mut remote_file)?;
        Ok(())
    })
    .unwrap_or_else(|e| {
        panic!(
            "Failed to scp {:?} to {UVM_NAME}:{to:?} because: {e}",
            env_tar_path
        )
    });

    info!(log, "Creating final docker image ...");
    let prepare_docker_script = &format!(
        r#"
set -e
cd /home/admin

mkdir /home/admin/root_env
tar -xf /home/admin/{ENV_TAR_ZST} -C root_env

docker load -i /config/image.tar

cat <<EOF > /home/admin/Dockerfile
FROM bazel/image:image
COPY root_env /home/root/root_env
RUN chmod 700 /home/root/root_env/{SSH_AUTHORIZED_PRIV_KEYS_DIR}
RUN chmod 600 /home/root/root_env/{SSH_AUTHORIZED_PRIV_KEYS_DIR}/*
EOF
docker build --tag final .

cat <<EOF > /home/admin/run
#!/bin/sh
docker run --name system_test --network host --env IC_VERSION_FILE={ic_version_file:?} final \
  /home/root/root_env/dependencies/{colocated_test_bin} \
  --working-dir /home/root --no-delete-farm-group --no-farm-keepalive --group-base-name {colocated_test} run
EOF
chmod +x /home/admin/run
"#,
    );
    uvm.block_on_bash_script_from_session(&session, prepare_docker_script)
        .unwrap_or_else(|e| panic!("Failed to create final docker image on UVM because: {e}"));
    info!(log, "Starting test remotely ...");
    start_test(session.clone());
    let test_result_handle = {
        info!(log, "Waiting for test results asynchronously ...");
        receive_test_exit_code_async(session, log.clone())
    };
    let ipv6 = uvm.get_vm().unwrap().ipv6;
    // We need a runtime to execute an async read_test_log_async in a sync context.
    // As there is only one lightweight task, we allocate min resources to the runtime.
    let rt: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("Could not create tokio runtime: {}", err));
    info!(log, "Reading test logs from journald asynchronously ...");
    let log_cloned = log.clone();
    let test_log_handle = rt.spawn(async move {
        // We start reading logs from the very beginning, which corresponds to the cursor="".
        let mut cursor = String::from("");
        loop {
            // In normal scenarios, i.e. without errors/interrupts, the function below should never return.
            // In case it returns unexpectedly, we restart reading logs from the checkpoint cursor.
            let result = read_test_log_async(ipv6, &mut cursor).await;
            if let Err(err) = result {
                error!(
                    log_cloned,
                    "Reading test logs failed unexpectedly with {err}"
                );
            }
            warn!(
                log_cloned,
                "Restart reading test logs from cursor after {} sec ...",
                RETRY_LOG_READ_DELAY.as_secs()
            );
            tokio::time::sleep(RETRY_LOG_READ_DELAY).await;
        }
    });
    let test_exit_code = test_result_handle
        .join()
        .expect("test execution thread failed");
    info!(
        log,
        "Wait extra {} sec to collect last uvm logs",
        EXTRA_TIME_LOG_COLLECTION.as_secs()
    );
    std::thread::sleep(EXTRA_TIME_LOG_COLLECTION);
    info!(log, "Stop reading logs from uvm");
    test_log_handle.abort();
    assert_eq!(0, test_exit_code, "test finished with failure");
    info!(log, "test execution has finished successfully");
}

fn start_test(session: Session) {
    let run_test_script = r#"
    set -E
    nohup sh -c '/home/admin/run > /dev/null 2>&1; echo $? > test_exit_code' &
    "#
    .to_string();
    let mut channel = session
        .channel_session()
        .expect("failed to establish channel");
    channel.exec("bash").unwrap();
    channel.write_all(run_test_script.as_bytes()).unwrap();
    channel.flush().unwrap();
    channel.send_eof().unwrap();
}

fn receive_test_exit_code_async(
    session: Session,
    log: slog::Logger,
) -> std::thread::JoinHandle<i32> {
    std::thread::spawn(move || {
        let test_exit_code_script = r#"
            set -e
            value=$(<test_exit_code)
            echo $value
        "#
        .to_string();
        loop {
            let mut output = String::new();
            let mut channel = session.channel_session().unwrap();
            channel.exec("bash").unwrap();
            channel.write_all(test_exit_code_script.as_bytes()).unwrap();
            channel.flush().unwrap();
            channel.send_eof().unwrap();
            channel.read_to_string(&mut output).unwrap();
            channel.wait_close().unwrap();
            let exit_code = channel.exit_status().unwrap();
            if exit_code == 0 {
                info!(log, "Test exited with code {output}.");
                return output
                    .trim()
                    .parse::<i32>()
                    .expect("Couldn't parse test exit code.");
            }
            std::thread::sleep(Duration::from_secs(10));
        }
    })
}

#[derive(Debug, Deserialize)]
struct JournalRecord {
    #[serde(rename = "__CURSOR")]
    cursor: String,
    #[serde(rename = "MESSAGE")]
    message: String,
}

async fn read_test_log_async(ipv6: Ipv6Addr, cursor: &mut String) -> anyhow::Result<()> {
    let socket_addr = std::net::SocketAddr::new(ipv6.into(), 19531);
    let mut stream = TcpSocket::new_v6()?.connect(socket_addr).await?;
    stream
        .write_all(b"GET /entries?CONTAINER_NAME=system_test&follow HTTP/1.1\n")
        .await?;
    stream.write_all(b"Accept: application/json\n").await?;
    let entries = format!("Range: entries={}:-1:\n\r\n\r", cursor);
    stream.write_all(entries.as_bytes()).await?;
    let buf_reader = BufReader::new(stream);
    let mut lines = buf_reader.lines();
    while let Some(line) = lines.next_line().await? {
        let record_result: Result<JournalRecord, serde_json::Error> = serde_json::from_str(&line);
        if let Ok(record) = record_result {
            println!("{}", record.message);
            // We update the cursor value with the current one.
            // In case function errors, we can start reading logs from this checkpointed cursor.
            *cursor = record.cursor;
        }
    }
    Ok(())
}
