use ic_canister_sandbox_backend_lib::run_canister_sandbox;
use ic_canister_sandbox_common::protocol;
use ic_canister_sandbox_common::protocol::ctlsvc;
use ic_canister_sandbox_common::rpc;
use ic_canister_sandbox_common::sandbox_client_stub::SandboxClientStub;
use ic_canister_sandbox_common::sandbox_service::SandboxService;
use ic_canister_sandbox_common::transport;
use std::sync::Arc;

use crate::controller_service_impl::ControllerServiceImpl;

/// Runs the sandboxing code in a new thread. The given
/// "ControllerService" object will be made acessible as "upcall" IPC
/// endpoint to the sandbox thread. The returned "SandboxService" is
/// the "downcall" IPC endpoint from replica to sandbox.
pub fn create_sandbox_thread(
    controller_service: Arc<ControllerServiceImpl>,
) -> Arc<dyn SandboxService> {
    let (sock_controller, sock_sandbox) = std::os::unix::net::UnixStream::pair().unwrap();

    // Run the sandbox code in a thread.
    std::thread::spawn(move || {
        run_canister_sandbox(sock_sandbox);
    });

    // Wrap with IPC layer.
    attach_ipc_service_to_socket(sock_controller, controller_service)
}

/// Wrap the given unix domain socket for bi-directional IPC services:
/// In the "sending" direction, we will use the "SandboxService"
/// interface, while on the "receiving" direction the
/// "ControllerService" is provided.
fn attach_ipc_service_to_socket(
    socket: std::os::unix::net::UnixStream,
    controller_service: Arc<dyn rpc::DemuxServer<ctlsvc::Request, ctlsvc::Reply> + Send + Sync>,
) -> Arc<dyn SandboxService> {
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
    // This is a very simplistic way of handling (no multiplexing),
    // to be replaced by proper I/O model later.
    std::thread::spawn(move || {
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

    svc
}
