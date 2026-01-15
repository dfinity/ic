use std::{
    collections::HashMap,
    os::unix::{net::UnixStream, prelude::FromRawFd},
    sync::{Arc, Condvar, Mutex},
};

use crate::{
    child_process_initialization,
    controller_launcher_client_stub::{self, ControllerLauncherClientStub},
    controller_launcher_service::ControllerLauncherService,
    launcher_service::LauncherService,
    process::spawn_socketed_process,
    protocol::{
        self,
        ctllaunchersvc::SandboxExitedRequest,
        launchersvc::{
            LaunchCompilerReply, LaunchCompilerRequest, LaunchSandboxReply, LaunchSandboxRequest,
            TerminateReply, TerminateRequest,
        },
    },
    rpc,
    transport::{self, SocketReaderConfig},
};
use ic_types::CanisterId;
use nix::{
    errno::Errno,
    sys::wait::{WaitStatus, wait},
    unistd::Pid,
};

/// The `main()` of the launcher binary. This function is called from
/// binaries such as `ic-replay` to run as a sandbox launcher.
///
pub fn sandbox_launcher_main() {
    let socket = child_process_initialization();
    let mut embedder_config_arg: Option<String> = None;

    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg.as_str() == "--embedder-config" {
            embedder_config_arg = args.next();
            break;
        }
    }

    run_launcher(
        socket,
        embedder_config_arg.expect("Missing embedder config."),
    );
}

pub fn run_launcher(socket: std::os::unix::net::UnixStream, embedder_config_arg: String) {
    let socket = Arc::new(socket);

    let out_stream =
        transport::UnixStreamMuxWriter::<protocol::transport::LauncherToController>::new(
            Arc::clone(&socket),
        );

    let request_out_stream = out_stream.make_sink::<protocol::ctllaunchersvc::Request>();
    let reply_out_stream = out_stream.make_sink::<protocol::launchersvc::Reply>();

    // Construct RPC channel client to controller.
    let reply_handler = Arc::new(rpc::ReplyManager::<protocol::ctllaunchersvc::Reply>::new());
    let controller = controller_launcher_client_stub::ControllerLauncherClientStub::new(Arc::new(
        rpc::Channel::new(request_out_stream, reply_handler.clone()),
    ));

    // Construct RPC server for launching sandbox processes.
    let svc = Arc::new(LauncherServer::new(controller, embedder_config_arg));

    // Wrap it all up to handle frames received on socket.
    let frame_handler = transport::Demux::<_, _, protocol::transport::ControllerToLauncher>::new(
        Arc::new(rpc::ServerStub::new(svc, reply_out_stream)),
        reply_handler.clone(),
    );

    // Run RPC operations on the stream socket.
    transport::socket_read_messages::<_, _>(
        move |message| {
            frame_handler.handle(message);
        },
        socket,
        SocketReaderConfig::default(),
    );
    reply_handler.flush_with_errors();
}

#[derive(Debug)]
struct ProcessInfo {
    canister_id: Option<CanisterId>,
    panic_on_failure: bool,
}
pub struct LauncherServer {
    pid_to_process_info: Arc<Mutex<HashMap<Pid, ProcessInfo>>>,
    has_children: Arc<Condvar>,
    embedder_config_arg: String,
}

impl LauncherServer {
    fn new(controller: ControllerLauncherClientStub, embedder_config_arg: String) -> Self {
        let pid_to_process_info = Arc::new(Mutex::new(HashMap::<Pid, ProcessInfo>::new()));
        let has_children = Arc::new(Condvar::new());
        let watcher_process_info_map = Arc::clone(&pid_to_process_info);
        let watcher_has_children = Arc::clone(&has_children);
        std::thread::Builder::new()
            .name("LauncherChildWatch".to_string())
            .spawn(move || loop {
                // Explicitly drop the lock on the id map before waiting on children
                // (to avoid a deadlock with the `launch_sandbox`).
                drop(
                    watcher_has_children
                        .wait_while(watcher_process_info_map.lock().unwrap(), |info_map| {
                            info_map.is_empty()
                        })
                        .unwrap(),
                );
                match wait() {
                    Err(err) => match err {
                        Errno::ECHILD => {
                            unreachable!("Launcher received ECHILD error");
                        }
                        _ => {
                            unreachable!("Launcher encountered error waiting on children: {}", err)
                        }
                    },
                    Ok(status) => match status {
                        WaitStatus::Exited(pid, 0) => {
                            watcher_process_info_map.lock().unwrap().remove(&pid);
                        }
                        WaitStatus::StillAlive => {}
                        _ => {
                            let pid = status
                                .pid()
                                .expect("WaitStatus is not StillAlive so it should have a pid");

                            let mut info_map = watcher_process_info_map.lock().unwrap();
                            let process_info = info_map.remove(&pid);
                            eprintln!(
                                "Sandbox pid {pid} for canister {process_info:?} exited unexpectedly with status {status:?}"
                            );

                            let should_panic = process_info
                                .as_ref()
                                .map(|x| x.panic_on_failure)
                                .unwrap_or(true);
                            if should_panic {
                                // If we have a canister id, tell the replica process to print its history.
                                if let Some(canister_id) = process_info.and_then(|x| x.canister_id)
                                {
                                    controller
                                        .sandbox_exited(SandboxExitedRequest { canister_id })
                                        .sync()
                                        .unwrap();
                                }
                                panic!("Launcher detected sandbox exit");
                            }
                        }
                    },
                }
            })
            .unwrap();
        Self {
            pid_to_process_info,
            has_children,
            embedder_config_arg,
        }
    }
}

impl LauncherService for LauncherServer {
    fn launch_sandbox(
        &self,
        LaunchSandboxRequest {
            sandbox_exec_path,
            argv,
            canister_id,
            socket,
        }: LaunchSandboxRequest,
    ) -> rpc::Call<LaunchSandboxReply> {
        match spawn_socketed_process(
            &sandbox_exec_path,
            &argv,
            &[("RUST_LIB_BACKTRACE", "0")],
            socket,
        ) {
            Ok(child_handle) => {
                // Ensure the launcher closes its end of the socket.
                drop(unsafe { UnixStream::from_raw_fd(socket) });

                let mut info_map = self.pid_to_process_info.lock().unwrap();

                // If there were no children before, then notify the waiting
                // thread that we have children.
                if info_map.is_empty() {
                    self.has_children.notify_one();
                }

                // Record the canister id associated with this process.
                let pid = child_handle.id();
                info_map.insert(
                    Pid::from_raw(pid as i32),
                    ProcessInfo {
                        canister_id: Some(canister_id),
                        panic_on_failure: true,
                    },
                );

                rpc::Call::new_resolved(Ok(LaunchSandboxReply { pid }))
            }
            Err(err) => {
                eprintln!("Error spawning sandbox process: {err}");
                rpc::Call::new_resolved(Err(rpc::Error::ServerError))
            }
        }
    }

    fn launch_compiler(
        &self,
        LaunchCompilerRequest {
            exec_path,
            argv,
            socket,
        }: LaunchCompilerRequest,
    ) -> rpc::Call<LaunchCompilerReply> {
        let mut args = argv.clone();
        args.push("--embedder-config".to_string());
        args.push(self.embedder_config_arg.clone());

        match spawn_socketed_process(&exec_path, &args, &[], socket) {
            Ok(child_handle) => {
                // Ensure the launcher closes its end of the socket.
                drop(unsafe { UnixStream::from_raw_fd(socket) });

                let mut info_map = self.pid_to_process_info.lock().unwrap();

                // If there were no children before, then notify the waiting
                // thread that we have children.
                if info_map.is_empty() {
                    self.has_children.notify_one();
                }

                // Record the canister id associated with this process.
                let pid = child_handle.id();
                info_map.insert(
                    Pid::from_raw(pid as i32),
                    ProcessInfo {
                        canister_id: None,
                        panic_on_failure: false,
                    },
                );

                rpc::Call::new_resolved(Ok(LaunchCompilerReply { pid }))
            }
            Err(err) => {
                eprintln!("Error spawning compiler process {exec_path}: {err}");
                rpc::Call::new_resolved(Err(rpc::Error::ServerError))
            }
        }
    }

    fn terminate(&self, _req: TerminateRequest) -> rpc::Call<TerminateReply> {
        std::process::exit(0);
    }
}
