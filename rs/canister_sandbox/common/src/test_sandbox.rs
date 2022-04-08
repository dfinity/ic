use ic_canister_sandbox_common::protocol::sbxsvc;
use ic_canister_sandbox_common::*;

use std::os::unix::io::FromRawFd;
use std::sync::Arc;

struct DummyMessageSink {}

impl<M> rpc::MessageSink<M> for DummyMessageSink {
    fn handle(&self, _cookie: u64, _msg: M) {}
}

struct DummySandboxService {}

/// RPC interface exposed by sandbox process.
impl sandbox_service::SandboxService for DummySandboxService {
    fn terminate(&self, _req: sbxsvc::TerminateRequest) -> rpc::Call<sbxsvc::TerminateReply> {
        println!("Sandbox: Received 'terminate' request");
        rpc::Call::new_resolved(Ok(sbxsvc::TerminateReply {}))
    }
    fn open_wasm(&self, _req: sbxsvc::OpenWasmRequest) -> rpc::Call<sbxsvc::OpenWasmReply> {
        println!("Sandbox: Received 'open_wasm' request");
        rpc::Call::new_resolved(Ok(sbxsvc::OpenWasmReply(Ok(()))))
    }
    fn close_wasm(&self, _req: sbxsvc::CloseWasmRequest) -> rpc::Call<sbxsvc::CloseWasmReply> {
        unimplemented!();
    }
    fn open_memory(&self, _req: sbxsvc::OpenMemoryRequest) -> rpc::Call<sbxsvc::OpenMemoryReply> {
        unimplemented!();
    }
    fn close_memory(
        &self,
        _req: sbxsvc::CloseMemoryRequest,
    ) -> rpc::Call<sbxsvc::CloseMemoryReply> {
        unimplemented!();
    }
    fn start_execution(
        &self,
        _req: sbxsvc::StartExecutionRequest,
    ) -> rpc::Call<sbxsvc::StartExecutionReply> {
        unimplemented!();
    }
    fn resume_execution(
        &self,
        _req: sbxsvc::ResumeExecutionRequest,
    ) -> rpc::Call<sbxsvc::ResumeExecutionReply> {
        unimplemented!()
    }
    fn create_execution_state(
        &self,
        _req: sbxsvc::CreateExecutionStateRequest,
    ) -> rpc::Call<sbxsvc::CreateExecutionStateReply> {
        unimplemented!()
    }
}

fn main() {
    // When started, we will receive the control socket as file descriptor 3.
    let socket = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
    let socket = Arc::new(socket);

    let out_stream =
        transport::UnixStreamMuxWriter::<protocol::transport::SandboxToController>::new(
            Arc::clone(&socket),
        );

    let _request_out_stream = out_stream.make_sink::<protocol::ctlsvc::Request>();
    let reply_out_stream = out_stream.make_sink::<sbxsvc::Reply>();

    let _request_handler = Arc::new(DummyMessageSink {});
    let reply_handler = Arc::new(DummyMessageSink {});

    let svc = Arc::new(DummySandboxService {});
    let demux = transport::Demux::<_, _, protocol::transport::ControllerToSandbox>::new(
        Arc::new(rpc::ServerStub::new(svc, reply_out_stream)),
        reply_handler,
    );

    // Just start handling stdin.
    transport::socket_read_messages::<_, _>(
        move |message| {
            demux.handle(message);
        },
        socket,
    );
}
