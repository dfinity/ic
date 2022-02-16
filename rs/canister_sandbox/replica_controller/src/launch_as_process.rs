use std::{os::unix::io::AsRawFd, process::Child};

use ic_types::CanisterId;
use std::sync::Arc;

use ic_canister_sandbox_common::{
    launcher_client_stub::LauncherClientStub,
    launcher_service::LauncherService,
    process::spawn_socketed_process,
    protocol::{
        self,
        launchersvc::{LaunchSandboxReply, LaunchSandboxRequest},
    },
    protocol::{ctllaunchersvc, ctlsvc},
    rpc,
    sandbox_client_stub::SandboxClientStub,
    sandbox_service::SandboxService,
    transport,
};

pub fn spawn_launcher_process(
    exec_path: &str,
    argv: &[String],
    controller_service: Arc<
        dyn rpc::DemuxServer<ctllaunchersvc::Request, ctllaunchersvc::Reply> + Send + Sync,
    >,
) -> std::io::Result<(Box<dyn LauncherService>, Child)> {
    let (socket, sock_launcher) = std::os::unix::net::UnixStream::pair()?;
    let child_handle = spawn_socketed_process(exec_path, argv, sock_launcher.as_raw_fd())?;

    let socket = Arc::new(socket);

    // Set up outgoing channel.
    let out = transport::UnixStreamMuxWriter::<protocol::transport::ControllerToLauncher>::new(
        Arc::clone(&socket),
    );

    // Construct RPC client to launcher process.
    let reply_handler = Arc::new(rpc::ReplyManager::<protocol::launchersvc::Reply>::new());
    let svc = Box::new(LauncherClientStub::new(rpc::Channel::new(
        out.make_sink::<protocol::launchersvc::Request>(),
        reply_handler.clone(),
    )));

    // Set up thread to handle incoming channel -- replies are routed
    // to reply buffer, requests to the RPC request handler given.
    let _ = std::thread::spawn(move || {
        let demux = transport::Demux::<_, _, protocol::transport::LauncherToController>::new(
            Arc::new(rpc::ServerStub::new(
                controller_service,
                out.make_sink::<protocol::ctllaunchersvc::Reply>(),
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

    Ok((svc, child_handle))
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
    canister_id: CanisterId,
    controller_service: Arc<dyn rpc::DemuxServer<ctlsvc::Request, ctlsvc::Reply> + Send + Sync>,
    launcher: &dyn LauncherService,
) -> std::io::Result<(Arc<dyn SandboxService>, u32, std::thread::JoinHandle<()>)> {
    let (sock_controller, sock_sandbox) = std::os::unix::net::UnixStream::pair()?;
    let request = LaunchSandboxRequest {
        sandbox_exec_path: exec_path.to_string(),
        argv: argv.to_vec(),
        canister_id,
        socket: sock_sandbox.as_raw_fd(),
    };
    let LaunchSandboxReply { pid } = launcher.launch_sandbox(request).sync()?;

    let socket = Arc::new(sock_controller);

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
        // Send a notification to the writer thread to stop.
        // Otherwise, the writer thread will remain waiting forever.
        out.stop();
    });

    Ok((svc, pid, thread_handle))
}

/// Spawns a sandbox process for the given canister.
pub fn create_sandbox_process(
    controller_service: Arc<dyn rpc::DemuxServer<ctlsvc::Request, ctlsvc::Reply> + Send + Sync>,
    launcher_service: &dyn LauncherService,
    canister_id: CanisterId,
    mut argv: Vec<String>,
) -> std::io::Result<(Arc<dyn SandboxService>, u32)> {
    assert!(!argv.is_empty());
    argv.push(canister_id.to_string());

    let (sandbox_handle, pid, _recv_thread_handle) = spawn_canister_sandbox_process(
        &argv[0],
        &argv[1..],
        canister_id,
        Arc::clone(&controller_service) as Arc<_>,
        launcher_service,
    )
    .expect("Failed to start sandbox process");
    Ok((sandbox_handle, pid))
}
