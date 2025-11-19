use candid::Principal;
use ic_registry_routing_table::CanisterIdRange;
use ic_types::PrincipalId;
use nix::sys::signal::Signal;
use pocket_ic::PocketIc;
use pocket_ic::common::rest::CanisterIdRange as RawCanisterIdRange;
use reqwest::Url;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;
use tempfile::NamedTempFile;

const LOCALHOST: &str = "127.0.0.1";

// this function is not used by all integration test suites => dead code allowed
#[allow(dead_code)]
pub fn raw_canister_id_range_into(r: &RawCanisterIdRange) -> CanisterIdRange {
    CanisterIdRange {
        start: PrincipalId(Principal::from_slice(&r.start.canister_id))
            .try_into()
            .unwrap(),
        end: PrincipalId(Principal::from_slice(&r.end.canister_id))
            .try_into()
            .unwrap(),
    }
}

// this function is not used by all integration test suites => dead code allowed
#[allow(dead_code)]
pub fn start_server_helper(
    test_driver_pid: Option<u32>,
    log_levels: Option<String>,
    capture_stdout: bool,
    capture_stderr: bool,
) -> (Url, Child) {
    let bin_path = std::env::var_os("POCKET_IC_BIN").expect("Missing PocketIC binary");
    let port_file_path = if let Some(test_driver_pid) = test_driver_pid {
        std::env::temp_dir().join(format!("pocket_ic_{test_driver_pid}.port"))
    } else {
        NamedTempFile::new().unwrap().into_temp_path().to_path_buf()
    };
    let mut cmd = Command::new(PathBuf::from(bin_path));
    cmd.arg("--port-file").arg(port_file_path.clone());
    if let Some(log_levels) = log_levels {
        cmd.arg("--log-levels").arg(log_levels);
    }
    // use a long TTL of 5 mins (the bazel test timeout for medium tests)
    // so that the server doesn't die during the test if the runner
    // is overloaded
    cmd.arg("--ttl").arg("300");
    if capture_stdout {
        cmd.stdout(std::process::Stdio::piped());
    }
    if capture_stderr {
        cmd.stderr(std::process::Stdio::piped());
    }
    let out = cmd.spawn().expect("Failed to start PocketIC binary");
    let url = loop {
        if let Ok(port_string) = std::fs::read_to_string(port_file_path.clone())
            && port_string.contains("\n")
        {
            let port: u16 = port_string
                .trim_end()
                .parse()
                .expect("Failed to parse port to number");
            break Url::parse(&format!("http://{LOCALHOST}:{port}/")).unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    (url, out)
}

// this function is not used by all integration test suites => dead code allowed
#[allow(dead_code)]
pub fn start_server() -> Url {
    let test_driver_pid = std::process::id();
    start_server_helper(Some(test_driver_pid), None, false, false).0
}

// this function is not used by all integration test suites => dead code allowed
#[allow(dead_code)]
pub fn send_signal_to_pic(pic: PocketIc, mut child: Child, shutdown_signal: Option<Signal>) {
    if let Some(signal) = shutdown_signal {
        // send shutdown signal to PocketIC server
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.id().try_into().unwrap()),
            signal,
        )
        .unwrap();
        let status = child.wait().unwrap();
        assert!(status.success());
        // the PocketIC instance can't be deleted and thus dropping the PocketIC instance panics
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(pic);
        }))
        .unwrap_err();
    } else {
        // Delete the PocketIC instance.
        drop(pic);
    }
}
