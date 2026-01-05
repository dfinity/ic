use anyhow::Result;
use ic_system_test_driver::driver::constants::COLOCATE_CONTAINER_NAME;
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::driver_setup::{
    SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR,
};
use ic_system_test_driver::driver::farm::HostFeature;
use ic_system_test_driver::driver::group::{CliArguments, SystemTestGroup};
use ic_system_test_driver::driver::ic::VmResources;
use ic_system_test_driver::driver::test_env::RequiredHostFeaturesFromCmdLine;
use ic_system_test_driver::driver::test_env::{TestEnv, TestEnvAttribute};
use ic_system_test_driver::driver::test_env_api::{
    FarmBaseUrl, SshSession, get_dependency_path, scp_recv_from, scp_send_to,
};
use ic_system_test_driver::driver::test_setup::GroupSetup;
use ic_system_test_driver::driver::universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms};
use itertools::Itertools;
use slog::{error, info};
use ssh2::Session;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::str;
use std::time::Duration;

const UVM_NAME: &str = "colocated-test-driver";
const COLOCATED_TEST: &str = "COLOCATED_TEST";
const COLOCATED_TEST_BIN: &str = "COLOCATED_TEST_BIN";
const EXTRA_TIME_LOG_COLLECTION: Duration = Duration::from_secs(10);

pub const RUNFILES_TAR_ZST: &str = "runfiles.tar.zst";
pub const ENV_TAR_ZST: &str = "env.tar.zst";
const DASHBOARDS_TAR_ZST: &str = "dashboards.tar.zst";

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
        .with_config_img(get_dependency_path(
            "rs/tests/colocate_uvm_config_image.zst",
        ));

    let uvm = if env::var("COLOCATED_TEST_DRIVER_VM_ENABLE_IPV4").is_ok() {
        uvm.enable_ipv4()
    } else {
        uvm
    };

    uvm.start(&env)
        .unwrap_or_else(|e| panic!("Failed to setup Universal VM {UVM_NAME} because: {e}"));
    info!(log, "Universal VM {UVM_NAME} installed!");

    // Create a tarball of the runfiles (runtime dependencies) such that they can be copied to the UVM.
    let runfiles_tar_path = env.get_path(RUNFILES_TAR_ZST);
    let runfiles = std::env::var("RUNFILES")
        .expect("Expected the environment variable RUNFILES to be defined!");
    info!(log, "Creating {runfiles_tar_path:?} ...");
    let output = Command::new("tar")
        .arg("--create")
        .arg("--file")
        .arg(&runfiles_tar_path)
        .arg("--auto-compress")
        .arg("--directory")
        .arg(runfiles)
        .arg("--dereference")
        .arg("--exclude=rs/tests/colocate_test_bin")
        .arg("--exclude=rs/tests/colocate_uvm_config_image.zst")
        // Avoid packing in ic-os images. Those are runtime dependencies for the
        // top-level test runner which uploads them to shared storage; after that
        // they are not used anymore and are only referenced by URL (propagated
        // through env vars).
        .arg("--exclude=**/*.tar.zst")
        .arg(".")
        .output()
        .unwrap_or_else(|e| panic!("Failed to tar the runfiles directory because: {e}"));

    if !output.status.success() {
        let err = str::from_utf8(&output.stderr).unwrap_or("");
        panic!("Tarring the runfiles directory failed with error: {err}");
    }

    // Create a tarball of some required files in the environment directory such that they can be copied to the UVM.
    let env_tar_path = env.get_path(ENV_TAR_ZST);
    info!(log, "Creating {env_tar_path:?} ...");
    let output = Command::new("tar")
        .arg("--create")
        .arg("--file")
        .arg(&env_tar_path)
        .arg("--auto-compress")
        .arg("--directory")
        .arg(env.base_path())
        .arg(Path::new(&FarmBaseUrl::attribute_name()).with_extension("json"))
        .arg(Path::new(&GroupSetup::attribute_name()).with_extension("json"))
        .arg(Path::new(SSH_AUTHORIZED_PUB_KEYS_DIR).join(SSH_USERNAME))
        .arg(Path::new(SSH_AUTHORIZED_PRIV_KEYS_DIR).join(SSH_USERNAME))
        .output()
        .unwrap_or_else(|e| panic!("Failed to tar the env directory because: {e}"));

    if !output.status.success() {
        let err = str::from_utf8(&output.stderr).unwrap_or("");
        panic!("Tarring the env directory failed with error: {err}");
    }

    let uvm = env.get_deployed_universal_vm(UVM_NAME).unwrap();

    info!(log, "Setting up SSH session to {UVM_NAME} UVM ...");
    let session = uvm
        .block_on_ssh_session()
        .unwrap_or_else(|e| panic!("Failed to setup SSH session to {UVM_NAME} because: {e}"));

    scp_send_to(
        log.clone(),
        &session,
        &runfiles_tar_path,
        &Path::new("/home/admin").join(RUNFILES_TAR_ZST),
        0o644,
    );
    scp_send_to(
        log.clone(),
        &session,
        &env_tar_path,
        &Path::new("/home/admin").join(ENV_TAR_ZST),
        0o644,
    );

    // Create a temporary environment file that we SCP into the UVM. These environment
    // variables are then forward to the docker container with --env-file.
    // (scoped to delete tempfile asap)
    {
        let tmpdir = tempfile::tempdir().expect("Could not create tempdir");
        let filepath = tmpdir.path().join("env");
        let mut file = File::create(filepath.clone()).expect("Could not create tempfile");

        // We remove some problematic (and unnecessary) environment variables
        // (docker/podman struggles to parse them)
        let output = Command::new("env")
            .env("BASH_FUNC_rlocation%%", "")
            .env("BASH_FUNC_is_absolute%%", "")
            .output()
            .unwrap_or_else(|e| panic!("Failed to list env: {e}"));

        file.write_all(&output.stdout).expect("Could not write env");

        scp_send_to(
            log.clone(),
            &session,
            &filepath,
            Path::new("/home/admin/env_vars"),
            0o644,
        );
    };

    let required_host_features = {
        if let Some(host_features) = env.read_host_features("colocated") {
            let features = host_features
                .iter()
                .map(|hf| serde_json::to_string(hf).unwrap())
                .collect::<Vec<String>>()
                .join(",");
            format!("--set-required-host-features={features}")
        } else {
            "".to_owned()
        }
    };

    // The user specified some dashboards to be used in the uvm
    let dashboards_uvm_host_path = format!("/home/admin/{DASHBOARDS_TAR_ZST}");
    let dashboards_path_in_docker = match std::env::var("IC_DASHBOARDS_DIR") {
        Ok(provided_path) => {
            info!(
                log,
                "Dashboards dir is specified and its contents will be copied over to the UVM"
            );

            let output = Command::new("tar")
                .arg("-cf")
                .arg(DASHBOARDS_TAR_ZST)
                .arg("-C")
                .arg(&provided_path)
                .arg(".")
                .output()
                .unwrap_or_else(|e| panic!("Failed to create a tar of dashboards because: {e}"));

            if !output.status.success() {
                let err = str::from_utf8(&output.stderr).unwrap_or("");
                panic!("Tarring the dashboards directory failed with error: {err}");
            }

            scp_send_to(
                log.clone(),
                &session,
                Path::new(&DASHBOARDS_TAR_ZST),
                Path::new(&dashboards_uvm_host_path),
                0o644,
            );
            provided_path
        }
        // Will be an empty dir in a resulting docker image
        // if the dashboards are not provided
        _ => "/home/root/dashboards".to_string(),
    };

    info!(log, "Creating final docker image ...");

    let forward_ssh_agent =
        env::var("COLOCATED_TEST_DRIVER_VM_FORWARD_SSH_AGENT").unwrap_or("".to_string());

    let metrics_flag = match env::var("ENABLE_METRICS") {
        Ok(val) if val == "1" || val.eq_ignore_ascii_case("true") => "--enable-metrics".to_string(),
        _ => "".to_string(),
    };

    let logs_flag = if env::var("VECTOR_VM_PATH").is_err() {
        "--no-logs".to_string()
    } else {
        "".to_string()
    };

    let cli_arguments = CliArguments::read_attribute(&env);
    let exclude_logs_args = cli_arguments
        .exclude_logs
        .iter()
        .flat_map(|pattern| ["--exclude-logs", pattern.as_str()])
        .join(" ");

    let prepare_docker_script = &format!(
        r#"
set -e

# Unpack uploaded tarballs under /home/admin/test which will become the test's working directory:
mkdir -p /home/admin/test
tar -xf /home/admin/{RUNFILES_TAR_ZST} --one-top-level="/home/admin/runfiles"
tar -xf /home/admin/{ENV_TAR_ZST} --one-top-level="/home/admin/test/root_env"
chmod 700 /home/admin/test/root_env/{SSH_AUTHORIZED_PRIV_KEYS_DIR}
chmod 600 /home/admin/test/root_env/{SSH_AUTHORIZED_PRIV_KEYS_DIR}/*
if [ -e "/home/admin/{DASHBOARDS_TAR_ZST}" ]; then
    tar -xf /home/admin/{DASHBOARDS_TAR_ZST} --one-top-level=/home/admin/dashboards
else
    mkdir -p /home/admin/dashboards
fi

docker load -i /config/ubuntu_test_runtime.tar

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
docker run \
  --name {COLOCATE_CONTAINER_NAME} \
  --network host \
  -v /home/admin/test:/home/root/test \
  -v /home/admin/runfiles:/home/root/runfiles \
  -v /home/admin/dashboards:{dashboards_path_in_docker}:ro \
  --env-file /home/admin/env_vars \
  --env RUNFILES=/home/root/runfiles \
  "${{DOCKER_RUN_ARGS[@]}}" \
  ubuntu_test_runtime:image \
  /home/root/runfiles/{colocated_test_bin} \
    --working-dir /home/root/test \
    --no-delete-farm-group --no-farm-keepalive \
    {required_host_features} \
    --group-base-name {colocated_test} \
    {metrics_flag} \
    {logs_flag} \
    {exclude_logs_args} \
    run
EOF
chmod +x /home/admin/run
"#,
    );
    uvm.block_on_bash_script_from_session(&session, prepare_docker_script)
        .unwrap_or_else(|e| panic!("Failed to create final docker image on UVM because: {e}"));
    info!(log, "Starting test remotely ...");
    start_test(env.clone(), &uvm);
    let test_result_handle = {
        info!(log, "Waiting for test results asynchronously ...");
        receive_test_exit_code_async(session.clone(), log.clone())
    };
    let test_exit_code = test_result_handle
        .join()
        .expect("test execution thread failed");

    fetch_test_dir(env.clone(), &uvm, &session);

    info!(
        log,
        "Wait extra {} sec to collect last uvm logs",
        EXTRA_TIME_LOG_COLLECTION.as_secs()
    );
    std::thread::sleep(EXTRA_TIME_LOG_COLLECTION);
    assert_eq!(0, test_exit_code, "test finished with failure");
    info!(log, "test execution has finished successfully");
}

fn start_test(env: TestEnv, uvm: &DeployedUniversalVm) {
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

fn fetch_test_dir(env: TestEnv, uvm: &DeployedUniversalVm, session: &Session) {
    let log = env.logger();
    let test_dir_tar = Path::new("/home/admin/test.tar");
    info!(
        log,
        "Tarring the test directory on the {UVM_NAME} to {test_dir_tar:?}..."
    );
    uvm.block_on_bash_script_from_session(
        session,
        &format!("sudo tar -cf {test_dir_tar:?} -C /home/admin/test ."),
    )
    .unwrap_or_else(|e| panic!("Failed to tar the test directory on {UVM_NAME} because: {e}"));
    let local_test_dir_tar = env.get_path("test.tar");
    info!(
        log,
        "Copying {test_dir_tar:?} from the {UVM_NAME} to the local test-driver at {local_test_dir_tar:?}..."
    );
    scp_recv_from(log.clone(), session, test_dir_tar, &local_test_dir_tar);
    let colocated_test_dir = env.get_path("colocated_test");
    info!(
        log,
        "Untarring the test directory from the {UVM_NAME} to {colocated_test_dir:?} ..."
    );
    let colocated_test_dir_str = colocated_test_dir.display();
    let mut cmd = Command::new("tar");
    cmd.arg("-x")
        .arg("-f")
        .arg(&local_test_dir_tar)
        .arg(format!("--one-top-level={colocated_test_dir_str}"));
    let output = cmd.output().unwrap_or_else(|e| {
        panic!("Failed to untar {local_test_dir_tar:?} directory because: {e}")
    });
    if !output.status.success() {
        let err = str::from_utf8(&output.stderr).unwrap_or("");
        panic!("Untarring {local_test_dir_tar:?} failed with error: {err}");
    }
    info!(
        log,
        "Untarred the test directory from the {UVM_NAME} to {colocated_test_dir:?}."
    );
}

fn receive_test_exit_code_async(
    session: Session,
    log: slog::Logger,
) -> std::thread::JoinHandle<i32> {
    std::thread::spawn(move || {
        loop {
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
                    error!(
                        log,
                        "Reading test exit code failed unexpectedly with err={err:?}. Retrying in {} sec",
                        TEST_STATUS_CHECK_RETRY.as_secs()
                    );
                    std::thread::sleep(TEST_STATUS_CHECK_RETRY);
                }
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
