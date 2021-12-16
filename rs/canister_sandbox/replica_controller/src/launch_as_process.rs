use std::{
    os::unix::{io::AsRawFd, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command},
};

use ic_canister_sandbox_backend_lib::RUN_AS_CANISTER_SANDBOX_FLAG;
use ic_types::CanisterId;
use once_cell::sync::OnceCell;
use std::os::unix::process::CommandExt;
use std::sync::Arc;

use ic_canister_sandbox_common::{
    protocol, protocol::ctlsvc, rpc, sandbox_client_stub::SandboxClientStub,
    sandbox_service::SandboxService, transport,
};

const SANDBOX_EXECUTABLE_NAME: &str = "canister_sandbox";

// These binaries support running in the canister sandbox mode.
const RUNNABLE_AS_SANDBOX: &[&str] = &["drun", "ic-replay"];

pub struct SocketedProcess {
    pub child_handle: Child,
    pub control_stream: UnixStream,
}

/// Spawns a subprocess and passes an (anonymous) unix domain socket to
/// it for control. The socket will arrive as file descriptor 3 in the
/// target process, and the other end of the socket will be returned
/// in this call to control the process.
pub fn spawn_socketed_process(
    exec_path: &str,
    argv: &[String],
) -> std::io::Result<SocketedProcess> {
    let (sock_controller, sock_sandbox) = std::os::unix::net::UnixStream::pair()?;

    let mut cmd = Command::new(exec_path);

    cmd.args(argv);

    // In case of Command we inherit the current process's environment. This should
    // particularly include things such as Rust backtrace flags. It might be
    // advisable to filter/configure that (in case there might be information in
    // env that the sandbox process should not be privy to).

    // The following block duplicates sock_sandbox fd under fd 3, errors are
    // handled.
    unsafe {
        cmd.pre_exec(move || {
            let fd = libc::dup2(sock_sandbox.as_raw_fd(), 3);

            if fd != 3 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })
    };

    let child_handle = cmd.spawn()?;

    Ok(SocketedProcess {
        child_handle,
        control_stream: sock_controller,
    })
}

/// Spawn a canister sandbox process and yield RPC interface object to
/// communicate with it. When the socket is closed by the other side,
/// we check if the safe_shutdown flag was set. If not this function
/// will initiate an exit (or a panic during testing).
///
/// # Panics & exit
///
/// This function panics upon socket close if safe_shutdown flag is
/// unset. The caller of the function is expected to set/unset the flag.
pub fn spawn_canister_sandbox_process(
    exec_path: &str,
    argv: &[String],
    controller_service: Arc<dyn rpc::DemuxServer<ctlsvc::Request, ctlsvc::Reply> + Send + Sync>,
) -> std::io::Result<(Arc<dyn SandboxService>, Child, std::thread::JoinHandle<()>)> {
    let SocketedProcess {
        child_handle,
        control_stream: socket,
    } = spawn_socketed_process(exec_path, argv)?;

    let socket = Arc::new(socket);

    // Set up outgoing channel.
    let out = transport::UnixStreamMuxWriter::<protocol::transport::ControllerToSandbox>::new(
        Arc::clone(&socket),
    );

    // Construct RPC client to sandbox process.
    let reply_handler = Arc::new(rpc::ReplyManager::<protocol::sbxsvc::Reply>::new());
    let svc = Arc::new(SandboxClientStub::new(rpc::Channel::new(
        out.make_sink::<protocol::sbxsvc::Request>(),
        reply_handler.clone(),
    )));

    // Set up thread to handle incoming channel -- replies are routed
    // to reply buffer, requests to the RPC request handler given.
    let thread_handle = std::thread::spawn(move || {
        let demux = transport::Demux::<_, _, protocol::transport::SandboxToController>::new(
            Arc::new(rpc::ServerStub::new(
                controller_service,
                out.make_sink::<protocol::ctlsvc::Reply>(),
            )),
            reply_handler,
        );
        transport::socket_read_messages::<_, _>(
            move |message| {
                demux.handle(message);
            },
            socket,
        );
    });

    Ok((svc, child_handle, thread_handle))
}

/// Spawns a sandbox process for the given canister.
pub fn create_sandbox_process(
    controller_service: Arc<dyn rpc::DemuxServer<ctlsvc::Request, ctlsvc::Reply> + Send + Sync>,
    canister_id: &CanisterId,
    mut argv: Vec<String>,
) -> std::io::Result<(Arc<dyn SandboxService>, Child)> {
    assert!(!argv.is_empty());
    argv.push(canister_id.to_string());

    let (sandbox_handle, child_handle, _recv_thread_handle) = spawn_canister_sandbox_process(
        &argv[0],
        &argv[1..],
        Arc::clone(&controller_service) as Arc<_>,
    )
    .expect("Failed to start sandbox process");
    Ok((sandbox_handle, child_handle))
}

/// Get the path of the current running binary.
fn current_binary_path() -> Option<PathBuf> {
    std::env::args().next().map(PathBuf::from)
}

/// Gets the executable and arguments for spawning a canister sandbox.
pub(super) fn create_sandbox_argv() -> Option<Vec<String>> {
    let current_binary_path = current_binary_path()?;
    let current_binary_name = current_binary_path.file_name()?.to_str()?;

    // The order of checks performed in this function is important.
    // Please do not reorder.
    //
    // 1. If the current binary supports running the sandbox mode, then use it.
    // This is important for `ic-replay` and `drun` where we do not control
    // the location of the sandbox binary.
    if RUNNABLE_AS_SANDBOX.contains(&current_binary_name) {
        let exec_path = current_binary_path.to_str()?.to_string();
        return Some(vec![exec_path, RUN_AS_CANISTER_SANDBOX_FLAG.to_string()]);
    }

    // 2. If the sandbox binary is in the same folder as the current binary, then
    // use it.
    let current_binary_folder = current_binary_path.parent()?;
    let sandbox_executable_path = current_binary_folder.join(SANDBOX_EXECUTABLE_NAME);
    if Path::exists(&sandbox_executable_path) {
        let exec_path = sandbox_executable_path.to_str()?.to_string();
        return Some(vec![exec_path]);
    }

    // 3. The two checks above cover all production use cases.
    // Find the sandbox binary for testing and local development.
    create_sandbox_argv_for_testing()
}

/// Only for testing purposes.
/// Gets executable and arguments when running in CI or in a dev environment.
fn create_sandbox_argv_for_testing() -> Option<Vec<String>> {
    // In CI we expect the sandbox executable to be in our path so this should
    // succeed.
    if let Ok(exec_path) = which::which(SANDBOX_EXECUTABLE_NAME) {
        println!("Running sandbox with executable {:?}", exec_path);
        return Some(vec![exec_path.to_str().unwrap().to_string()]);
    }

    static SANDBOX_COMPILED: OnceCell<()> = OnceCell::new();

    // When running in a dev environment we expect `cargo` to be in our path and
    // we should be able to find the workspace cargo manifest so this should
    // succeed.
    match (
        which::which("cargo"),
        top_level_cargo_manifest_for_testing(),
    ) {
        (Ok(path), Some(manifest_path)) => {
            println!(
                "Building sandbox with cargo {:?} and manifest {:?}",
                path, manifest_path
            );
            let path = path.to_str().unwrap().to_string();
            SANDBOX_COMPILED
                .get_or_init(|| build_sandbox_with_cargo_for_testing(&path, &manifest_path));
            // Run `canister_sandbox` using `cargo run` so that we don't need to find the
            // executable in the target folder.
            Some(make_cargo_argv_for_testing(
                &path,
                &manifest_path,
                CargoCommandType::Run,
            ))
        }
        _ => None,
    }
}

/// Only for testing purposes.
/// Finds the topmost cargo manifest in the directory path of the current
/// manifest.
fn top_level_cargo_manifest_for_testing() -> Option<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok();
    let mut next_parent = manifest_dir.as_ref().map(Path::new);
    let mut current_manifest = None;
    while let Some(parent) = next_parent {
        let next: PathBuf = [parent, Path::new("Cargo.toml")].iter().collect();
        if next.exists() {
            current_manifest = Some(next);
        }
        next_parent = parent.parent();
    }
    current_manifest
}

/// Only for testing purposes.
fn build_sandbox_with_cargo_for_testing(cargo_path: &str, manifest_path: &Path) {
    let argv = make_cargo_argv_for_testing(cargo_path, manifest_path, CargoCommandType::Build);
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .expect("Failed to build canister_sandbox with cargo");
    if !output.status.success() {
        panic!(
            "Failed to build canister_sandbox with cargo\nError: {:?}\nstderr: {:?}",
            output.status, output.stderr
        )
    }
}

enum CargoCommandType {
    Build,
    Run,
}

/// Only for testing purposes.
fn make_cargo_argv_for_testing(
    cargo_path: &str,
    manifest_path: &Path,
    cargo_command_type: CargoCommandType,
) -> Vec<String> {
    let common_args = vec![
        "--quiet",
        "--manifest-path",
        manifest_path.to_str().unwrap(),
        "--bin",
        SANDBOX_EXECUTABLE_NAME,
    ];
    let argv = match cargo_command_type {
        CargoCommandType::Run => vec![vec![cargo_path, "run"], common_args, vec!["--"]],
        CargoCommandType::Build => vec![vec![cargo_path, "build"], common_args],
    };
    argv.into_iter()
        .map(|s| s.into_iter().map(|s| s.to_string()))
        .flatten()
        .collect()
}
