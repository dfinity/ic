use ic_tests::driver::test_env::RequiredHostFeaturesFromCmdLine;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::str;
use std::time::Duration;
use std::{env, fs};
#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::constants::SSH_USERNAME;
use ic_tests::driver::driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR};
use ic_tests::driver::farm::HostFeature;
use ic_tests::driver::group::{SystemTestGroup, COLOCATE_CONTAINER_NAME};
use ic_tests::driver::ic::VmResources;
use ic_tests::driver::test_env::{TestEnv, TestEnvAttribute};
use ic_tests::driver::test_env_api::{retry, FarmBaseUrl, HasDependencies, SshSession};
use ic_tests::driver::test_setup::GroupSetup;
use ic_tests::driver::universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms};
use ic_tests::retry_with_msg;
use slog::{debug, error, info};
use ssh2::Session;

const UVM_NAME: &str = "test-driver";
const COLOCATED_TEST: &str = "COLOCATED_TEST";
const COLOCATED_TEST_BIN: &str = "COLOCATED_TEST_BIN";
const EXTRA_TIME_LOG_COLLECTION: Duration = Duration::from_secs(10);

pub const ENV_TAR_ZST: &str = "env.tar.zst";

pub const SCP_RETRY_TIMEOUT: Duration = Duration::from_secs(60);
pub const SCP_RETRY_BACKOFF: Duration = Duration::from_secs(5);
pub const TEST_STATUS_CHECK_RETRY: Duration = Duration::from_secs(5);
type ExitCode = i32;

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

    let host_features: Vec<HostFeature> =
        env::var("COLOCATED_TEST_DRIVER_VM_REQUIRED_HOST_FEATURES")
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
            .unwrap_or_default();

    let vm_resources: VmResources = env::var("COLOCATED_TEST_DRIVER_VM_RESOURCES")
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .unwrap_or_default();

    let uvm = UniversalVm::new(UVM_NAME.to_string())
        .with_required_host_features(host_features)
        .with_vm_resources(vm_resources)
        .with_config_img(env.get_dependency_path("rs/tests/colocate_uvm_config_image.zst"));

    let uvm = if env::var("COLOCATED_TEST_DRIVER_VM_ENABLE_IPV4").is_ok() {
        uvm.enable_ipv4()
    } else {
        uvm
    };

    uvm.start(&env)
        .unwrap_or_else(|e| panic!("Failed to setup Universal VM {UVM_NAME} because: {e}"));
    info!(log, "Universal VM {UVM_NAME} installed!");

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
    retry_with_msg!(
        format!(
            "scp-ing {:?} of {:?} KiB to {UVM_NAME}:{to:?}",
            env_tar_path,
            size / 1024,
        ),
        env.logger(),
        SCP_RETRY_TIMEOUT,
        SCP_RETRY_BACKOFF,
        || {
            let mut remote_file = session.scp_send(&to, 0o644, size, None)?;
            let mut from_file = File::open(env_tar_path.clone())?;
            std::io::copy(&mut from_file, &mut remote_file)?;
            Ok(())
        }
    )
    .unwrap_or_else(|e| {
        panic!(
            "Failed to scp {:?} to {UVM_NAME}:{to:?} because: {e}",
            env_tar_path
        )
    });
    info!(
        log,
        "scp-ed {:?} of {:?} KiB to {UVM_NAME}:{to:?} .",
        env_tar_path,
        size / 1024,
    );

    let docker_env_vars = {
        let mut env_vars = String::from("");
        for (key, value) in env::vars() {
            // NOTE: we use "ENV_DEPS__" as prefix for env variables, which are passed to system-tests via Bazel.
            if key.starts_with("ENV_DEPS__") {
                env_vars.push_str(format!(r#"--env {key}={value:?} \"#).as_str());
            }
        }
        env_vars
    };

    let required_host_features = {
        if let Some(host_features) = env.read_host_features("colocated") {
            let features = host_features
                .iter()
                .map(|hf| serde_json::to_string(hf).unwrap())
                .collect::<Vec<String>>()
                .join(",");
            format!("--set-required-host-features={}", features)
        } else {
            "".to_owned()
        }
    };

    debug!(log, "Docker env vars: {docker_env_vars}");

    info!(log, "Creating final docker image ...");

    let forward_ssh_agent =
        env::var("COLOCATED_TEST_DRIVER_VM_FORWARD_SSH_AGENT").unwrap_or("".to_string());

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

cat <<'EOF' > /home/admin/run
#!/bin/sh
if [ "{forward_ssh_agent}" ] && [ -n "${{SSH_AUTH_SOCK:-}}" ] && [ -e "${{SSH_AUTH_SOCK:-}}" ]; then
    DOCKER_RUN_ARGS+=(
        -v "$SSH_AUTH_SOCK:/ssh-agent"
        -e SSH_AUTH_SOCK="/ssh-agent"
    )
else
    echo "No ssh-agent to forward."
fi
docker run --name {COLOCATE_CONTAINER_NAME} --network host \
  {docker_env_vars}
  "${{DOCKER_RUN_ARGS[@]}}" \
  final \
  /home/root/root_env/dependencies/{colocated_test_bin} \
  --working-dir /home/root --no-delete-farm-group --no-farm-keepalive {required_host_features} --group-base-name {colocated_test} run
EOF
chmod +x /home/admin/run
"#,
    );
    uvm.block_on_bash_script_from_session(&session, prepare_docker_script)
        .unwrap_or_else(|e| panic!("Failed to create final docker image on UVM because: {e}"));
    info!(log, "Starting test remotely ...");
    start_test(env, uvm);
    let test_result_handle = {
        info!(log, "Waiting for test results asynchronously ...");
        receive_test_exit_code_async(session, log.clone())
    };
    let test_exit_code = test_result_handle
        .join()
        .expect("test execution thread failed");
    info!(
        log,
        "Wait extra {} sec to collect last uvm logs",
        EXTRA_TIME_LOG_COLLECTION.as_secs()
    );
    std::thread::sleep(EXTRA_TIME_LOG_COLLECTION);
    assert_eq!(0, test_exit_code, "test finished with failure");
    info!(log, "test execution has finished successfully");
}

fn start_test(env: TestEnv, uvm: DeployedUniversalVm) {
    let run_test_script = r#"
    set -E
    nohup sh -c '/home/admin/run > /dev/null 2>&1; echo $? > test_exit_code' &
    "#;

    let vm = uvm.get_vm().unwrap();
    let ipv6 = vm.ipv6.to_string();
    let priv_key_path = env
        .get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
        .join(SSH_USERNAME);
    let mut cmd = Command::new("ssh");
    cmd.stdin(Stdio::piped())
        .arg(format!("{SSH_USERNAME}@{ipv6}"))
        .arg("-i")
        .arg(priv_key_path);
    if env::var("COLOCATED_TEST_DRIVER_VM_FORWARD_SSH_AGENT").is_ok() {
        cmd.arg("-A");
    }
    let mut ssh_child = cmd
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg("-oStrictHostKeyChecking=no")
        .arg("bash")
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to SSH to the test-driver VM because {e:?}"));

    let mut stdin = ssh_child.stdin.take().expect("Failed to open stdin of ssh");
    std::thread::spawn(move || {
        stdin
            .write_all(run_test_script.as_bytes())
            .expect("Failed to write to stdin");
    });

    let out = ssh_child
        .wait_with_output()
        .expect("Failed to read stdout of ssh");
    std::io::stdout().write_all(&out.stdout).unwrap();
    std::io::stderr().write_all(&out.stderr).unwrap();
    if !out.status.success() {
        panic!("Failed to ssh to the test-driver VM!");
    }
}

fn receive_test_exit_code_async(
    session: Session,
    log: slog::Logger,
) -> std::thread::JoinHandle<i32> {
    std::thread::spawn(move || loop {
        match check_test_exit_code(&session) {
            Ok(result) => {
                if let Some(exit_code) = result {
                    info!(log, "Test execution finished with exit code {exit_code}.");
                    return exit_code;
                } else {
                    // Test execution hasn't finished yet, wait a bit and retry.
                    std::thread::sleep(TEST_STATUS_CHECK_RETRY);
                }
            }
            Err(err) => {
                error!(log, "Reading test exit code failed unexpectedly with err={err:?}. Retrying in {} sec",
                TEST_STATUS_CHECK_RETRY.as_secs());
                std::thread::sleep(TEST_STATUS_CHECK_RETRY);
            }
        }
    })
}

fn check_test_exit_code(session: &Session) -> Result<Option<ExitCode>> {
    // Try to read exit code of the test execution from the file `test_exit_code`.
    // If file doesn't yet exist, it means that the test is still running.
    let test_exit_code_script = r#"
            set -e
            value=$(<test_exit_code)
            echo $value
        "#
    .to_string();
    let mut output = String::new();
    let mut channel = session.channel_session()?;
    channel.exec("bash")?;
    channel.write_all(test_exit_code_script.as_bytes())?;
    channel.flush()?;
    channel.send_eof()?;
    channel.read_to_string(&mut output)?;
    channel.wait_close()?;
    let cmd_exit_code = channel.exit_status()?;
    if cmd_exit_code == 0 {
        let test_exit_code = output
            .trim()
            .parse::<i32>()
            .expect("Couldn't parse test exit code.");
        return Ok(Some(test_exit_code));
    }
    // Test is still running.
    Ok(None)
}
