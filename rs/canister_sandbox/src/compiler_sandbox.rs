use serde::{Deserialize, Serialize};
use std::os::unix::{net::UnixStream, prelude::FromRawFd};
use std::sync::Arc;

use crate::launcher_service::LauncherService;
use crate::protocol::transport::{Message, WireMessage};
use crate::{rpc, transport, transport::UnixStreamMuxWriter};
use ic_embedders::{CompilationResult, SerializedModule, WasmtimeEmbedder, wasm_utils};
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_logger::{ReplicaLogger, error, trace};
use ic_wasm_types::WasmEngineError;

// A helper used for actual compilation in the compiler sandbox
fn compile_and_serialize(
    embedder: &WasmtimeEmbedder,
    wasm_src: Vec<u8>,
) -> HypervisorResult<(CompilationResult, SerializedModule)> {
    let wasm =
        wasm_utils::decoding::decode_wasm(embedder.config().wasm_max_size, Arc::new(wasm_src))?;
    let (_cache, res) = wasm_utils::compile(embedder, &wasm);
    res
}

fn unexpected(desc: &str) -> HypervisorError {
    HypervisorError::WasmEngineError(WasmEngineError::Unexpected(desc.to_string()))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PlainWasm {
    #[serde(with = "serde_bytes")]
    pub wasm_src: Vec<u8>,
}

impl crate::fdenum::EnumerateInnerFileDescriptors for PlainWasm {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CompiledWasm {
    result: HypervisorResult<(CompilationResult, SerializedModule)>,
}

impl crate::fdenum::EnumerateInnerFileDescriptors for CompiledWasm {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}

impl crate::transport::MuxInto<WireMessage<PlainWasm, CompiledWasm>> for CompiledWasm {
    fn wrap(self, cookie: u64) -> WireMessage<PlainWasm, CompiledWasm> {
        WireMessage {
            cookie,
            msg: crate::protocol::transport::Message::Reply(self),
        }
    }
}

pub struct WasmCompilerProxy {
    socket_a: Arc<UnixStream>,
    rpc: crate::rpc::Channel<PlainWasm, CompiledWasm>,
    log: ReplicaLogger,
}

impl WasmCompilerProxy {
    pub fn start(
        log: ReplicaLogger,
        launcher: &dyn LauncherService,
        exec_path: &str,
        argv: &[String],
    ) -> HypervisorResult<Self> {
        let (socket_a, socket_b) = UnixStream::pair()
            .map_err(|e| unexpected(&format!("Failed to create a socket: {e}")))?;
        use std::os::unix::io::AsRawFd;

        let _ignore = launcher
            .launch_compiler(crate::protocol::launchersvc::LaunchCompilerRequest {
                exec_path: exec_path.to_string(),
                argv: argv.to_vec(),
                socket: socket_b.as_raw_fd(),
            })
            .sync();

        let socket_a = Arc::new(socket_a);
        let send_worker =
            UnixStreamMuxWriter::<WireMessage<PlainWasm, CompiledWasm>>::new(socket_a.clone());
        let tx = send_worker.make_sink::<PlainWasm>();

        let reply_collector = Arc::new(crate::rpc::ReplyManager::<CompiledWasm>::new());
        let channel = crate::rpc::Channel::new(tx, reply_collector.clone());

        let _read_worker_handle = {
            let log = log.clone();
            let socket_a = socket_a.clone();
            std::thread::Builder::new()
                .name("CompilerProxySocketReader".to_string())
                .spawn(move || {
                    let reply_collector_clone = reply_collector.clone();
                    transport::socket_read_messages::<_, _>(
                        move |message: WireMessage<PlainWasm, CompiledWasm>| match message.msg {
                            Message::Request(_) => {
                                error!(
                                log,
                                "Compiler proxy received a request. This is unexpected. Cookie: {}",
                                message.cookie
                            );
                            }
                            Message::Reply(w) => {
                                use rpc::MessageSink;
                                reply_collector.handle(message.cookie, w);
                            }
                        },
                        socket_a,
                        crate::SocketReaderConfig::default(),
                    );
                    send_worker.stop();
                    reply_collector_clone.flush_with_errors(); // We are shutting down. No more replies will come
                })
                .map_err(|e| {
                    unexpected(&format!(
                        "Compiler proxy failed to spawn socket reader thread: {e}"
                    ))
                })?
        };

        Ok(Self {
            socket_a,
            rpc: channel,
            log,
        })
    }

    pub fn initiate_stop(&self) {
        // The compiler process should shut down when the socket is closed
        let _ignore = self.socket_a.shutdown(std::net::Shutdown::Both);
    }

    pub fn compile(
        &self,
        wasm_src: Vec<u8>,
    ) -> HypervisorResult<(CompilationResult, SerializedModule)> {
        let req = PlainWasm { wasm_src };
        match self.rpc.call(req, Ok).sync() {
            Ok(compiled_wasm) => compiled_wasm.result,
            Err(_rpc_err) => {
                let msg = "Compiler RPC error. Possibly compiler died".to_string();
                error!(&self.log, "{}", msg);
                Err(HypervisorError::WasmEngineError(WasmEngineError::Other(
                    msg,
                )))
            }
        }
    }
}

impl Drop for WasmCompilerProxy {
    fn drop(&mut self) {
        self.initiate_stop();
    }
}

pub fn compiler_sandbox_main() {
    let logger_config = ic_config::logger::Config {
        log_destination: ic_config::logger::LogDestination::Stderr,
        level: ic_config::logger::Level::Warning,
        ..Default::default()
    };
    let (log, _log_guard) = ic_logger::new_replica_logger_from_config(&logger_config);
    let mut embedder_config_arg: Option<crate::EmbeddersConfig> = None;

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
    let config = embedder_config_arg
        .expect("Error from the sandbox process due to unknown embedder config.");

    rayon::ThreadPoolBuilder::new()
        .num_threads(config.num_rayon_compilation_threads)
        .build_global()
        .unwrap();

    let embedder = Arc::new(ic_embedders::WasmtimeEmbedder::new(config, log.clone()));

    let socket = unsafe { UnixStream::from_raw_fd(3) };
    let socket = Arc::new(socket);
    let send_worker =
        UnixStreamMuxWriter::<WireMessage<PlainWasm, CompiledWasm>>::new(socket.clone());
    let tx = send_worker.make_sink::<CompiledWasm>();

    let log_clone = log.clone();
    transport::socket_read_messages::<_, _>(
        move |message: WireMessage<PlainWasm, CompiledWasm>| match message.msg {
            Message::Request(w) => {
                trace!(log, "Compile request received. Cookie: {}", message.cookie);
                let result = compile_and_serialize(&embedder, w.wasm_src);
                let cw = CompiledWasm { result };
                let call = rpc::Call::new_resolved(Ok(cw));
                let call = rpc::Call::new_wrap(call, |x| x);
                tx.handle(message.cookie, call.sync().unwrap());
            }
            Message::Reply(_) => {
                error!(
                    log,
                    "Compiler received a reply. This is unexpected. Cookie: {}", message.cookie
                );
            }
        },
        socket,
        transport::SocketReaderConfig::for_sandbox(),
    );

    send_worker.stop();
    trace!(log_clone, "Compiler shut down gracefully");
}
