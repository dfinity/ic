use ic_types::CanisterId;
use nix::unistd::Pid;
use std::os::unix::{io::AsRawFd, net::UnixStream};

use ic_canister_sandbox_common::{
    protocol, protocol::ctlsvc, rpc, sandbox_client_stub::SandboxClientStub,
    sandbox_service::SandboxService, transport,
};

use std::sync::Arc;

pub struct SocketedProcess {
    pub pid: libc::pid_t,
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

    let exec_path = std::ffi::CString::new(exec_path.as_bytes())?;

    // Copy full current environment to sandbox process. This particularly
    // includes things such as Rust backtrace flags. It might be advisable
    // to filter/configure that (in case there might be information in
    // env that the sandbox process should not be privy to).
    let mut env = collect_env();
    let envp = make_null_terminated_string_array(&mut env);

    let mut argv = collect_argv(argv);
    let argvp = make_null_terminated_string_array(&mut argv);

    let pid = unsafe {
        // Unsafe section required due to raw call to libc posix_spawn function
        // as well as raw handling of raw file descriptor.
        // Safety is assured, cf. posix_spawn API.
        let mut pid = std::mem::MaybeUninit::<libc::pid_t>::uninit().assume_init();
        let mut file_actions =
            std::mem::MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit().assume_init();
        let mut attr = std::mem::MaybeUninit::<libc::posix_spawnattr_t>::uninit().assume_init();

        libc::posix_spawn_file_actions_init(&mut file_actions);
        libc::posix_spawn_file_actions_adddup2(&mut file_actions, sock_sandbox.as_raw_fd(), 3);
        libc::posix_spawnattr_init(&mut attr);

        let spawn_result = libc::posix_spawn(
            &mut pid,
            exec_path.as_ptr(),
            &file_actions,
            &attr,
            argvp.as_ptr(),
            envp.as_ptr(),
        );

        libc::posix_spawn_file_actions_destroy(&mut file_actions);
        libc::posix_spawnattr_destroy(&mut attr);

        if spawn_result != 0 {
            return Err(std::io::Error::last_os_error());
        }

        pid
    };

    Ok(SocketedProcess {
        pid,
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
) -> std::io::Result<(Arc<dyn SandboxService>, Pid, std::thread::JoinHandle<()>)> {
    let SocketedProcess {
        pid,
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
        transport::socket_read_demux::<_, _, _>(demux, socket);
    });

    Ok((svc, Pid::from_raw(pid), thread_handle))
}

pub fn create_sandbox_process(
    controller_service: Arc<dyn rpc::DemuxServer<ctlsvc::Request, ctlsvc::Reply> + Send + Sync>,
    canister_id: &CanisterId,
) -> Arc<dyn SandboxService> {
    let exec_path = if let Ok(path) = std::env::var("CANISTER_SANDBOX_BIN_PATH") {
        path
    } else {
        build_sandbox_binary_relative_path("canister_sandbox")
            .expect("No canister_sandbox binary found.")
    };

    let canister_id = format!("{}", canister_id);

    let (sandbox_handle, _pid, _recv_thread_handle) = spawn_canister_sandbox_process(
        &exec_path,
        &[exec_path.clone(), canister_id],
        Arc::clone(&controller_service) as Arc<_>,
    )
    .expect("Failed to start sandbox process");

    sandbox_handle
}

// Collects environment variables as vector of strings of "key=value"
// pairs (as is expected on process spawn).
fn collect_env() -> Vec<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::env::vars_os()
        .map(|(key, value)| {
            std::ffi::CString::new(
                [
                    key.as_os_str().as_bytes(),
                    &[b'='],
                    value.as_os_str().as_bytes(),
                ]
                .concat(),
            )
            .unwrap()
        })
        .collect::<Vec<std::ffi::CString>>()
}

// Collects strings as FFI strings (for use to convert argv array).
fn collect_argv(argv: &[String]) -> Vec<std::ffi::CString> {
    argv.iter()
        .map(|s| std::ffi::CString::new(s.as_bytes()).unwrap())
        .collect::<Vec<std::ffi::CString>>()
}

// Produces a null-terminated array of pointers from strings
// (i.e. "char* const*" for use in execve-like calls).
fn make_null_terminated_string_array(
    strings: &mut Vec<std::ffi::CString>,
) -> Vec<*mut libc::c_char> {
    let mut result = Vec::<*mut libc::c_char>::new();
    for s in strings {
        result.push(s.as_ptr() as *mut libc::c_char);
    }
    result.push(std::ptr::null::<libc::c_char>() as *mut libc::c_char);

    result
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
