pub mod compiler_sandbox;
pub mod controller_client_stub;
pub mod controller_launcher_client_stub;
pub mod controller_launcher_service;
pub mod controller_service;
mod dts;
pub mod frame_decoder;
pub mod launcher;
pub mod launcher_client_stub;
pub mod launcher_service;
pub mod logging;
pub mod process;
pub mod replica_controller;
pub mod rpc;
pub mod sandbox_client_stub;
pub mod sandbox_manager;
pub mod sandbox_server;
pub mod sandbox_service;
pub mod transport;
pub mod protocol {
    pub mod ctllaunchersvc;
    pub mod ctlsvc;
    pub mod id;
    pub mod launchersvc;
    pub mod logging;
    pub mod sbxsvc;
    pub mod structs;
    pub mod transport;
}
pub mod fdenum;

use protocol::{
    ctllaunchersvc, ctlsvc, launchersvc, sbxsvc,
    transport::{
        ControllerToLauncher, ControllerToSandbox, LauncherToController, Message,
        SandboxToController, WireMessage,
    },
};

use ic_config::embedders::Config as EmbeddersConfig;
use ic_logger::new_replica_logger_from_config;
use std::{
    os::unix::{net::UnixStream, prelude::FromRawFd},
    sync::Arc,
};
use transport::SocketReaderConfig;

/// This command line flag switches some binaries (ic-replica) into the
/// canister sandbox mode.
pub const RUN_AS_CANISTER_SANDBOX_FLAG: &str = "--run-as-canister-sandbox";

/// This command line flag switches some binaries (ic-replica) into the
/// launcher mode.
pub const RUN_AS_SANDBOX_LAUNCHER_FLAG: &str = "--run-as-sandbox-launcher";

/// This command line flag switches some binaries (ic-replica) into the
/// compiler mode.
pub const RUN_AS_COMPILER_SANDBOX_FLAG: &str = "--run-as-compiler-sandbox";

/// Magic signature to be exported by binaries which can work as a sandbox
pub const SANDBOX_SECTION_NAME: &str = ".canister_sandbox";
pub const SANDBOX_MAGIC_BYTES: [u8; 8] = [0x5d, 0xbe, 0xe2, 0x80, 0x4b, 0x10, 0xc6, 0x43];

// Declare how messages are multiplexed on channels between the controller <->
// (sandbox or launcher).

impl<Request, Reply> transport::MessageDemux<Request, Reply> for WireMessage<Request, Reply> {
    fn split(self) -> Option<(u64, transport::RequestOrReply<Request, Reply>)> {
        let WireMessage { cookie, msg } = self;
        match msg {
            Message::Request(req) => Some((cookie, transport::RequestOrReply::Request(req))),
            Message::Reply(rep) => Some((cookie, transport::RequestOrReply::Reply(rep))),
        }
    }
}

impl<Request, Reply> transport::MuxInto<WireMessage<Request, Reply>> for Request {
    fn wrap(self, cookie: u64) -> WireMessage<Request, Reply> {
        WireMessage {
            cookie,
            msg: Message::Request(self),
        }
    }
}

// The following impls are needed because a generic impl for the `Reply` type
// would conflict with the generic `Request` impl in the case where the `Reply`
// and `Request` types were equal.

impl transport::MuxInto<ControllerToSandbox> for ctlsvc::Reply {
    fn wrap(self, cookie: u64) -> ControllerToSandbox {
        WireMessage {
            cookie,
            msg: Message::Reply(self),
        }
    }
}

impl transport::MuxInto<SandboxToController> for sbxsvc::Reply {
    fn wrap(self, cookie: u64) -> SandboxToController {
        WireMessage {
            cookie,
            msg: Message::Reply(self),
        }
    }
}

impl transport::MuxInto<ControllerToLauncher> for ctllaunchersvc::Reply {
    fn wrap(self, cookie: u64) -> ControllerToLauncher {
        WireMessage {
            cookie,
            msg: Message::Reply(self),
        }
    }
}

impl transport::MuxInto<LauncherToController> for launchersvc::Reply {
    fn wrap(self, cookie: u64) -> LauncherToController {
        WireMessage {
            cookie,
            msg: Message::Reply(self),
        }
    }
}

/// Common setup to start the sandbox and launcher executables.
pub fn child_process_initialization() -> UnixStream {
    // The unsafe section is required to accept  the raw file descriptor received by
    // spawning the process -- cf. spawn_socketed_process function which
    // provides the counterpart and assures safety of this operation.
    let socket = unsafe { UnixStream::from_raw_fd(3) };

    // We abort the whole program with a core dump if a single thread panics.
    // This way we can capture all the context if a critical error
    // happens.
    abort_on_panic();

    socket
}

fn abort_on_panic() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        default_hook(panic_info);
        std::process::abort();
    }));
}
/// The `main()` of the canister sandbox binary. This function is called from
/// binaries such as `ic-replay` to run as a canister sandbox.
///
/// It sets up for operation and then hands over control to the
/// RPC management system.
///
/// Sandbox processes are spawned by the replica passing in a control
/// file descriptor as file descriptor number 3 (in addition to
/// stdin/stdout/stderr). This descriptor is a unix domain socket
/// used for RPC. The RPCs are bidirectional: The sandbox process
/// receives execution and management instructions from the controller
/// process, and it calls for system call and execution state change
/// operations into the controller.
pub fn canister_sandbox_main() {
    let socket = child_process_initialization();
    let mut embedder_config_arg = None;

    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg.as_str() == "--embedder-config" {
            let config_arg = args.next().expect("Missing embedder config.");
            embedder_config_arg = Some(
                serde_json::from_str(config_arg.as_str())
                    .expect("Could not parse the argument, invalid embedder config value."),
            )
        }
    }
    let embedder_config = embedder_config_arg
        .expect("Error from the sandbox process due to unknown embedder config.");

    // Currently Wasmtime uses the default rayon thread-pool with a thread per core.
    // In production this results in 64 threads. The number of threads is set to 8,
    // which is used for parallel page copying in the page allocator.
    // The compilation rayon threads are now only used in the compiler sandbox.
    rayon::ThreadPoolBuilder::new()
        .num_threads(EmbeddersConfig::default().num_rayon_page_allocator_threads)
        .build_global()
        .unwrap();

    run_canister_sandbox(socket, embedder_config);
}

/// Runs the canister sandbox service in the calling thread. The service
/// will use the given unix domain socket as its only means of
/// communication. It expects execution IPC commands to passed as
/// inputs on this communication channel, and will communicate
/// completions as well as auxiliary requests back on this channel.
pub fn run_canister_sandbox(
    socket: std::os::unix::net::UnixStream,
    embedder_config: EmbeddersConfig,
) {
    // TODO(RUN-204): Get the logger config from the replica instead of
    // hardcoding the parameters.
    let logger_config = ic_config::logger::Config {
        log_destination: ic_config::logger::LogDestination::Stderr,
        level: ic_config::logger::Level::Warning,
        ..Default::default()
    };
    let (log, _log_guard) = new_replica_logger_from_config(&logger_config);

    let socket = Arc::new(socket);

    let out_stream =
        transport::UnixStreamMuxWriter::<protocol::transport::SandboxToController>::new(
            Arc::clone(&socket),
        );

    let request_out_stream = out_stream.make_sink::<protocol::ctlsvc::Request>();
    let reply_out_stream = out_stream.make_sink::<protocol::sbxsvc::Reply>();

    // Construct RPC channel client to controller.
    let reply_handler = Arc::new(rpc::ReplyManager::<protocol::ctlsvc::Reply>::new());
    let controller = Arc::new(controller_client_stub::ControllerClientStub::new(Arc::new(
        rpc::Channel::new(request_out_stream, reply_handler.clone()),
    )));

    // Construct RPC server for the  service offered by this binary,
    // namely access to the sandboxed canister runner functions.
    let svc = Arc::new(sandbox_server::SandboxServer::new(
        sandbox_manager::SandboxManager::new(controller, embedder_config, log),
    ));

    // Wrap it all up to handle frames received on socket -- either
    // replies to our outgoing requests, or incoming requests to the
    // RPC service offered by this binary.
    let frame_handler = transport::Demux::<_, _, protocol::transport::ControllerToSandbox>::new(
        Arc::new(rpc::ServerStub::new(svc, reply_out_stream)),
        reply_handler.clone(),
    );

    // It is fine if we fail to spawn this thread. Used for fault
    // injection only.
    let inject_failure = std::env::var("SANDBOX_TESTING_ON_MALICIOUS_SHUTDOWN_MANUAL").is_ok();
    if inject_failure {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            std::process::exit(1);
        });
    }

    // Run RPC operations on the stream socket.
    transport::socket_read_messages::<_, _>(
        move |message| {
            frame_handler.handle(message);
        },
        socket,
        SocketReaderConfig::for_sandbox(),
    );
    reply_handler.flush_with_errors();
}

#[cfg(feature = "fuzzing_code")]
#[macro_export]
macro_rules! embed_sandbox_signature {
    () => {
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".canister_sandbox")]
        #[used]
        static SANDBOX_SIGNATURE: [u8; 8] = SANDBOX_MAGIC_BYTES;
    };
}
