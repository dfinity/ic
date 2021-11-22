use nix::unistd::Pid;
use std::os::unix::{io::AsRawFd, net::UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
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

    let mut env = collect_env();
    let envp = make_null_terminated_string_array(&mut env);

    let mut argv = collect_argv(argv);
    let argvp = make_null_terminated_string_array(&mut argv);

    let pid = unsafe {
        // Unsafe section required due to raw call to libc posix_spawn function
        // as well as raw handling of raw file descriptor.
        // Safety is assured, cf. posix_spawn API.
        let mut pid = std::mem::MaybeUninit::<libc::pid_t>::uninit();
        let file_actions = std::ptr::null_mut::<libc::posix_spawn_file_actions_t>();
        let attr = std::ptr::null_mut::<libc::posix_spawnattr_t>();

        libc::posix_spawn_file_actions_init(file_actions);
        libc::posix_spawn_file_actions_adddup2(file_actions, sock_sandbox.as_raw_fd(), 3);
        libc::posix_spawnattr_init(attr);

        let spawn_result = libc::posix_spawn(
            pid.as_mut_ptr(),
            exec_path.as_ptr(),
            file_actions,
            attr,
            argvp.as_ptr(),
            envp.as_ptr(),
        );

        libc::posix_spawn_file_actions_destroy(file_actions);
        libc::posix_spawnattr_destroy(attr);

        if spawn_result != 0 {
            return Err(std::io::Error::last_os_error());
        }

        pid.assume_init()
    };

    Ok(SocketedProcess {
        pid,
        control_stream: sock_controller,
    })
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
