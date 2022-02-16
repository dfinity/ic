pub mod controller_client_stub;
pub mod controller_launcher_client_stub;
pub mod controller_launcher_service;
pub mod controller_service;
pub mod frame_decoder;
pub mod launcher_client_stub;
pub mod launcher_service;
pub mod process;
pub mod rpc;
pub mod sandbox_client_stub;
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
use std::os::unix::{net::UnixStream, prelude::FromRawFd};

use protocol::{
    ctllaunchersvc, ctlsvc, launchersvc, sbxsvc,
    transport::{
        ControllerToLauncher, ControllerToSandbox, LauncherToController, Message,
        SandboxToController, WireMessage,
    },
};

/// This command line flag switches some binaries (ic-replica, drun) into the
/// canister sandbox mode.
pub const RUN_AS_CANISTER_SANDBOX_FLAG: &str = "--run-as-canister-sandbox";

/// This command line flag switches some binaries (ic-replica, drun) into the
/// launcher mode.
pub const RUN_AS_SANDBOX_LAUNCHER_FLAG: &str = "--run-as-sandbox-launcher";

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
