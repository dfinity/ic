///! Load sink for ic-workload-generator. Accepts any request and returns
///! a query-call response with an incrementing counter value, to show
///! theoretical max performance.
///!
///! TODO:
///!  - command line flag for IP:port to listen on
///!  - command line flag for THREAD_COUNT
///!  - could probably be made faster

use atomic_counter::AtomicCounter;
use serde::Serialize;
use std::io::Cursor;
use std::str::FromStr;
use tiny_http::{Response, Server, StatusCode};
use std::thread;
use std::sync::Arc;
use std::ops::Deref;

// Could have used types / methods from ic-* but wanted this to be as
// standalone as possible to demonstrate theoretical maximum performance.
#[derive(Serialize)]
struct Reply {
    #[serde(with = "serde_bytes")]
    arg: Vec<u8>
}

#[derive(Serialize)]
struct CanisterResponse {
    status: String,
    reply: Reply,
}

/// Number of threads processing incoming requests
const THREAD_COUNT: usize = 512;

fn main() {
    let mut guards = Vec::with_capacity(THREAD_COUNT);

    let server = Arc::new(Server::http("127.0.0.1:8080").unwrap());

    let counter = Arc::new(atomic_counter::RelaxedCounter::new(0));

    for _ in 0 ..THREAD_COUNT {
        let server = server.clone();
        let counter_ref = counter.clone();

        let guard = thread::spawn(move || {
            let header = tiny_http::Header::from_str("Content-Type: application/cbor").unwrap();
            let headers = vec![header];
            let counter = counter_ref.deref();

            loop {
                let request = match server.recv() {
                    Ok(rq) => rq,
                    Err(e) => {
                        println!("error: {}", e);
                        break;
                    }
                };

                let val = counter.inc();
                let bytes = u32::to_le_bytes(val as u32);

                let canister_response = CanisterResponse {
                    status: "replied".to_string(),
                    reply: Reply {
                        arg: bytes.to_vec(),
                    },
                };

                let data = serde_cbor::to_vec(&canister_response).expect("to_vec failed");
                let data_len = *&data.len();

                let response = Response::new(
                    StatusCode::from(200),
                    headers.clone(),
                    Cursor::new(data),
                    Some(data_len),
                    None,
                );

                let _ = request.respond(response);
            }
        });
        guards.push(guard);
    }

    for guard in guards {
        let _ = guard.join();
    }
}
