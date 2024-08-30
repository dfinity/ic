use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, SystemTime};

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Time,
    AdvanceTime(Duration),
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum Response {
    Ok,
    Time(SystemTime),
}

#[test]
fn test() {
    let state_machine_binary =
        std::env::var_os("STATE_MACHINE_BIN").expect("missing state machine binary binary");
    let mut child = Command::new(state_machine_binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to start test state machine");

    let mut child_in = child.stdin.take().unwrap();
    let mut child_out = child.stdout.take().unwrap();

    call_state_machine::<()>(
        Request::AdvanceTime(Duration::from_secs(1000)),
        &mut child_in,
        &mut child_out,
    );

    let time: SystemTime = call_state_machine(Request::Time, &mut child_in, &mut child_out);
    assert_eq!(
        time.duration_since(SystemTime::UNIX_EPOCH).unwrap(),
        Duration::from_nanos(1_620_329_630_000_000_000)
    );
}

fn call_state_machine<T: DeserializeOwned>(
    request: Request,
    stdin: &mut ChildStdin,
    stdout: &mut ChildStdout,
) -> T {
    send_request(request, stdin);
    read_response(stdout)
}

fn send_request(request: Request, child_in: &mut ChildStdin) {
    let mut cbor = vec![];
    ciborium::ser::into_writer(&request, &mut cbor).expect("bug: failed to encode a block");
    child_in
        .write_all(&(cbor.len() as u64).to_le_bytes())
        .expect("failed to send request length");
    child_in
        .write_all(cbor.as_slice())
        .expect("failed to send request data");
    child_in.flush().expect("failed to flush child stdin");
}

fn read_response<T: DeserializeOwned>(child_out: &mut ChildStdout) -> T {
    let vec = read_bytes(8, child_out);
    let size = usize::from_le_bytes(TryFrom::try_from(vec).expect("failed to read data size"));
    ciborium::from_reader(&read_bytes(size, child_out)[..]).unwrap()
}

fn read_bytes(num_bytes: usize, child_out: &mut ChildStdout) -> Vec<u8> {
    let mut buf = vec![0u8; num_bytes];
    child_out
        .read_exact(&mut buf)
        .expect("failed to read from child_stdout");
    buf
}
