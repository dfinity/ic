/// This is the canister sandbox process binary main entrance point.
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
use ic_canister_sandbox_backend_lib::run_canister_sandbox;
use std::os::unix::io::FromRawFd;

fn main() {
    // The unsafe section is required to accept  the raw file descriptor received by
    // spawning the process -- cf. spawn_socketed_process function which
    // provides the counterpart and assures safety of this operation.
    let socket = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };

    run_canister_sandbox(socket);
}
