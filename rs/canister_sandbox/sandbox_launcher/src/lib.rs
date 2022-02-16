use std::{
    collections::HashMap,
    os::unix::{net::UnixStream, prelude::FromRawFd},
    sync::{Arc, Condvar, Mutex},
    thread,
};

use ic_canister_sandbox_common::{
    child_process_initialization,
    controller_launcher_client_stub::{self, ControllerLauncherClientStub},
    controller_launcher_service::ControllerLauncherService,
    launcher_service::LauncherService,
    process::spawn_socketed_process,
    protocol::{
        self,
        ctllaunchersvc::SandboxExitedRequest,
        launchersvc::{LaunchSandboxReply, LaunchSandboxRequest},
    },
    rpc, transport,
};
use ic_types::CanisterId;
use nix::{
    errno::Errno,
    sys::wait::{wait, WaitStatus},
    unistd::Pid,
};

/// The `main()` of the launcher binary. This function is called from
/// binaries such as `ic-replay` and `drun` to run as a sandbox launcher.
///
pub fn sandbox_launcher_main() {
    let socket = child_process_initialization();
    run_launcher(socket);
}

pub fn run_launcher(socket: std::os::unix::net::UnixStream) {
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
    let svc = Arc::new(LauncherServer::new(controller));

    // Wrap it all up to handle frames received on socket.
    let frame_handler = transport::Demux::<_, _, protocol::transport::ControllerToLauncher>::new(
        Arc::new(rpc::ServerStub::new(svc, reply_out_stream)),
        reply_handler,
    );

    // Run RPC operations on the stream socket.
    transport::socket_read_messages::<_, _>(
        move |message| {
            frame_handler.handle(message);
        },
        socket,
    );
}

pub struct LauncherServer {
    pid_to_canister_id: Arc<Mutex<HashMap<Pid, CanisterId>>>,
    has_children: Arc<Condvar>,
}

impl LauncherServer {
    fn new(controller: ControllerLauncherClientStub) -> Self {
        let pid_to_canister_id = Arc::new(Mutex::new(HashMap::new()));
        let has_children = Arc::new(Condvar::new());
        let watcher_canister_id_map = Arc::clone(&pid_to_canister_id);
        let watcher_has_children = Arc::clone(&has_children);
        thread::spawn(move || loop {
            // Explicitly drop the lock on the id map before waiting on children
            // (to avoid a deadlock with the `launch_sandbox`).
            drop(
                watcher_has_children
                    .wait_while(watcher_canister_id_map.lock().unwrap(), |id_map| {
                        id_map.is_empty()
                    })
                    .unwrap(),
            );
            match wait() {
                Err(err) => match err {
                    Errno::ECHILD => {
                        unreachable!("Launcher recieved ECHILD error");
                    }
                    _ => unreachable!("Launcher encountered error waiting on children: {}", err),
                },
                Ok(status) => match status {
                    WaitStatus::Exited(pid, status) if status == 0 => {
                        watcher_canister_id_map.lock().unwrap().remove(&pid);
                    }
                    WaitStatus::StillAlive => {}
                    _ => {
                        let pid = status
                            .pid()
                            .expect("WaitStatus is not StillAlive so it should have a pid");
                        let mut canister_ids = watcher_canister_id_map.lock().unwrap();
                        let canister_id = canister_ids.remove(&pid);
                        eprintln!(
                            "Sandbox pid {} for canister {:?} exited unexpectedly with status {:?}",
                            pid, canister_id, status
                        );
                        // If we have a canister id, tell the replica process to print its history.
                        if let Some(canister_id) = canister_id {
                            controller
                                .sandbox_exited(SandboxExitedRequest { canister_id })
                                .sync()
                                .unwrap();
                        }
                        panic!("Launcher detected sandbox exit");
                    }
                },
            }
        });
        Self {
            pid_to_canister_id,
            has_children,
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
        match spawn_socketed_process(&sandbox_exec_path, &argv, socket) {
            Ok(child_handle) => {
                // Ensure the launcher closes its end of the socket.
                drop(unsafe { UnixStream::from_raw_fd(socket) });

                let mut id_map = self.pid_to_canister_id.lock().unwrap();

                // If there were no children before, then notify the waiting
                // thread that we have children.
                if id_map.is_empty() {
                    self.has_children.notify_one();
                }

                // Record the canister id associated with this process.
                let pid = child_handle.id();
                id_map.insert(Pid::from_raw(pid as i32), canister_id);

                rpc::Call::new_resolved(Ok(LaunchSandboxReply { pid }))
            }
            Err(err) => {
                eprintln!("Error spawning sandbox process: {}", err);
                rpc::Call::new_resolved(Err(rpc::Error::ServerError))
            }
        }
    }
}
