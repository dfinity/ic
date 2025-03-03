use nix::unistd::Pid;
use std::io::BufRead;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::{CommandExt, RawFd};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::transport::SocketReaderConfig;
use crate::{
    protocol, protocol::ctlsvc, rpc, sandbox_client_stub::SandboxClientStub,
    sandbox_service::SandboxService, transport,
};

use std::sync::Arc;

/// Copy a prefixed child output (reader) into the replica's output (writer).
fn copying_task<R, W>(prefix: &'static str, reader: Option<R>, mut writer: W)
where
    R: std::io::Read + Send + 'static,
    W: std::io::Write + Send + 'static,
{
    let Some(reader) = reader else {
        return;
    };
    let reader = std::io::BufReader::new(reader);
    for line in reader.lines() {
        let Ok(line) = line else {
            break;
        };
        let out = format!("{prefix}{line}\n");
        let _res = writer.write_all(out.as_bytes());
    }
}

/// Spawns a subprocess and passes the given unix domain socket to
/// it for control. The socket will arrive as file descriptor 3 in the
/// target process.
pub fn spawn_socketed_process(
    prefix: &'static str,
    exec_path: &str,
    argv: &[String],
    env: &[(&str, &str)],
    socket: RawFd,
) -> std::io::Result<Child> {
    let mut cmd = Command::new(exec_path);
    cmd.args(argv);
    for (k, v) in env {
        cmd.env(k, v);
    }

    // In case of Command we inherit the current process's environment. This should
    // particularly include things such as Rust backtrace flags. It might be
    // advisable to filter/configure that (in case there might be information in
    // env that the sandbox process should not be privy to).

    // The following block duplicates sock_sandbox fd under fd 3, errors are
    // handled.
    unsafe {
        cmd.pre_exec(move || {
            let fd = libc::dup2(socket, 3);

            if fd != 3 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })
    };

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child_handle = cmd.spawn()?;

    let child_stdout = child_handle.stdout.take();
    rayon::spawn(move || copying_task(prefix, child_stdout, std::io::stdout()));
    let child_stderr = child_handle.stderr.take();
    rayon::spawn(move || copying_task(prefix, child_stderr, std::io::stderr()));

    Ok(child_handle)
}

/// Only used for testing setups.
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

/// Only used for testing setups.
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
    let (socket, sock_sandbox) = std::os::unix::net::UnixStream::pair()?;
    let pid = spawn_socketed_process(
        "[TEST SANDBOX]: ",
        exec_path,
        argv,
        &[],
        sock_sandbox.as_raw_fd(),
    )?
    .id() as i32;

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
    let thread_handle = std::thread::Builder::new()
        .name("CanisterSandboxIPC".to_string())
        .spawn(move || {
            let demux = transport::Demux::<_, _, protocol::transport::SandboxToController>::new(
                Arc::new(rpc::ServerStub::new(
                    controller_service,
                    out.make_sink::<protocol::ctlsvc::Reply>(),
                )),
                reply_handler.clone(),
            );
            transport::socket_read_messages::<_, _>(
                move |message| {
                    demux.handle(message);
                },
                socket,
                SocketReaderConfig::default(),
            );
            reply_handler.flush_with_errors();
            // If we the connection drops, but it is not terminated from
            // our end, that implies that the sandbox process died. At
            // that point we need to terminate replica as we have no way
            // to progress execution safely, and we can not restart
            // execution in a deterministic and safe manner that will not
            // corrupt the state.
            if !safe_shutdown.load(Ordering::SeqCst) {
                abort_and_shutdown();
            }
        })
        .unwrap();

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

/// Build path to the sandbox executable relative to this executable's
/// path (using argv[0]). This allows easily locating the sandbox
/// executable provided it is in the same path as the main replica.
pub fn build_sandbox_binary_relative_path(sandbox_executable_name: &str) -> Option<String> {
    let argv0 = std::env::args().next()?;
    let this_exec_path = std::path::Path::new(&argv0);
    let parent = this_exec_path.parent()?;
    Some(parent.join(sandbox_executable_name).to_str()?.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn spawn_socketed_process_does_not_fail() {
        let res = spawn_socketed_process(
            "[TEST]: ",
            "/bin/sh",
            &[
                "-c".into(),
                r#"
                echo "stdout 1.1\n  stdout 1.2"; echo "stderr 1.1\n  stderr 1.2" 1>&2
                sleep 1
                echo "stdout 2.1\n  stdout 2.2"; echo "stderr 2.1\n  stderr 2.2" 1>&2
            "#
                .into(),
            ],
            &[],
            0,
        );
        let mut child = res.expect("Error spawning a process");
        rayon::spawn(move || {
            for i in 0..10 {
                println!("main output {i}");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        child.wait().expect("Error waiting a process");
    }

    use std::io;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct SharedWriter<W>(Arc<Mutex<W>>);

    impl<W: Write> SharedWriter<W> {
        pub fn new(w: W) -> Self {
            SharedWriter(Arc::new(Mutex::new(w)))
        }
    }

    impl<W: Write> Write for SharedWriter<W> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            (*self.0.lock().unwrap())
                .write_all(buf)
                .expect("Error writing to a shared buffer");
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            (*self.0.lock().unwrap()).flush()
        }
    }

    impl<W: Clone> SharedWriter<W> {
        pub fn get(&self) -> W {
            (*self.0.lock().unwrap()).clone()
        }
    }

    #[test]
    fn copying_task_prefixes_lines() {
        fn pfx(s: &str, expected: &str) {
            let reader = Cursor::new(s.to_string());
            let writer = SharedWriter::new(Vec::new());
            rayon::in_place_scope(|_scope| copying_task("pfx ", Some(reader), writer.clone()));
            assert_eq!(
                writer.get(),
                expected.as_bytes(),
                "Error asserting {:?} == {expected:?}",
                String::from_utf8_lossy(&writer.get())
            );
        }
        pfx("line\n", "pfx line\n");
        pfx("line", "pfx line\n");
        pfx("line1\nline2\n", "pfx line1\npfx line2\n");
        pfx("line1\nline2", "pfx line1\npfx line2\n");
        // Binary output is supported.
        pfx(
            &String::from_utf8_lossy(&[0_u8; 1234]),
            &format!("pfx {}\n", String::from_utf8_lossy(&[0_u8; 1234])),
        );
    }
}
