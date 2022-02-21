use nix::unistd::Pid;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::{CommandExt, RawFd};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    protocol, protocol::ctlsvc, rpc, sandbox_client_stub::SandboxClientStub,
    sandbox_service::SandboxService, transport,
};

use std::sync::Arc;

/// Spawns a subprocess and passes the given unix domain socket to
/// it for control. The socket will arrive as file descriptor 3 in the
/// target process.
pub fn spawn_socketed_process(
    exec_path: &str,
    argv: &[String],
    socket: RawFd,
) -> std::io::Result<Child> {
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
            let fd = libc::dup2(socket, 3);

            if fd != 3 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })
    };

    let child_handle = cmd.spawn()?;

    Ok(child_handle)
}

/// Spawn a canister sandbox process and yield RPC interface object to
/// communicate with it.
///
/// # Panics & exit
///
/// This function panics upon socket close if safe_shutdown flag is
/// unset. The caller of the function is expected to set/unset the flag.
pub fn spawn_canister_sandbox_process(
    exec_path: &str,
    argv: &[String],
    controller_service: Arc<dyn rpc::DemuxServer<ctlsvc::Request, ctlsvc::Reply> + Send + Sync>,
    safe_shutdown: Arc<AtomicBool>,
) -> std::io::Result<(Arc<dyn SandboxService>, Pid, std::thread::JoinHandle<()>)> {
    spawn_canister_sandbox_process_with_factory(exec_path, argv, controller_service, safe_shutdown)
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
pub fn spawn_canister_sandbox_process_with_factory(
    exec_path: &str,
    argv: &[String],
    controller_service: Arc<dyn rpc::DemuxServer<ctlsvc::Request, ctlsvc::Reply> + Send + Sync>,
    safe_shutdown: Arc<AtomicBool>,
) -> std::io::Result<(Arc<dyn SandboxService>, Pid, std::thread::JoinHandle<()>)> {
    let (socket, sock_sandbox) = std::os::unix::net::UnixStream::pair()?;
    let pid = spawn_socketed_process(exec_path, argv, sock_sandbox.as_raw_fd())?.id() as i32;

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
        // If we the connection drops, but it is not terminated from
        // our end, that implies that the sandbox process died. At
        // that point we need to terminate replica as we have no way
        // to progress execution safely, and we can not restart
        // execution in a deterministic and safe manner that will not
        // corrupt the state.
        if !safe_shutdown.load(Ordering::SeqCst) {
            abort_and_shutdown();
        }
    });

    Ok((svc, Pid::from_raw(pid), thread_handle))
}

// Terminate the replica process.
#[inline(always)]
fn abort_and_shutdown() {
    // Write now we simply exit abruptly. In the future, we need to
    // signal and wait for safe state flushing.
    let test_environment = std::env::var("SANDBOX_TESTING_ON_MALICIOUS_SHUTDOWN").is_ok();
    if test_environment {
        // We are in test mode, so we want to panic, so testing
        // can catch it.
        panic!("sandbox_abort_via_test");
    } else {
        unsafe {
            libc::exit(1);
        }
    }
}

/// Build path to the sandbox executable relative to this executable's
/// path (using argv[0]). This allows easily locating the sandbox
/// executable provided it is in the same path as the main replica.
pub fn build_sandbox_binary_relative_path(sandbox_executable_name: &str) -> Option<String> {
    let argv0 = std::env::args().next()?;
    let this_exec_path = std::path::Path::new(&argv0);
    let parent = this_exec_path.parent()?;
    Some(parent.join(sandbox_executable_name).to_str()?.to_string())
}
