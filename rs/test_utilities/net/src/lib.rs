//! Networking helpers for tests.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

/// A loopback TCP listener whose accept queue has been saturated so that any
/// further connect to [`addr`](Self::addr) neither completes nor is refused —
/// it hangs until the connecting side's own timeout fires. This lets tests
/// exercise connect-timeout code paths without requiring network egress.
///
/// Keep this value alive for as long as the address must stay unconnectable:
/// dropping it closes the listener (freeing the port) and the blocker
/// connections (emptying the accept queue), after which the address behaves
/// normally again.
pub struct SaturatedTcpListener {
    addr: SocketAddr,
    _listener: TcpListener,
    _blockers: Vec<TcpStream>,
}

impl SaturatedTcpListener {
    /// The saturated loopback address. Connecting to it neither completes nor
    /// is refused: it hangs until the connecting side's own timeout fires.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Bind a loopback listener with a minimal backlog and never accept from it.
/// Once its accept queue is full the kernel silently drops further SYNs (see
/// `tcp_conn_request`/`sk_acceptq_is_full`), so a fresh TCP connect neither
/// completes nor is refused: it hangs until the connecting side's connect
/// timeout fires. This exercises connect-timeout paths using only loopback, so
/// callers do not require network egress. (A non-routable address like
/// 10.255.255.1 only times out when a default route exists to black-hole the
/// packets; without one the OS returns an immediate "network unreachable"
/// error instead.)
///
/// Panics if the accept queue cannot be saturated, keeping callers
/// deterministic. See [`SaturatedTcpListener`] for lifetime requirements.
pub async fn saturated_loopback_listener() -> SaturatedTcpListener {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(1).unwrap();
    let addr = listener.local_addr().unwrap();

    // Fill the accept queue with connections that are never accepted. We keep
    // the successful ones alive so the queue stays full; the queue is saturated
    // once a fresh connect no longer completes but hangs.
    //
    // The loop is self-terminating (it stops as soon as a connect hangs), so
    // the bound is just a safety cap to avoid running away. With `listen(1)`
    // the queue saturates after `backlog + 1 = 2` connects on Linux
    // (`sk_acceptq_is_full`), so the 3rd connect already hangs; 16 leaves a
    // generous margin and is far above any real accept-queue capacity for this
    // backlog.
    let mut blockers = Vec::new();
    let mut saturated = false;
    for _ in 0..16 {
        match tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
            // Connect succeeded quickly: still room in the queue, keep it alive
            // and keep filling.
            Ok(Ok(stream)) => blockers.push(stream),
            // Connect hung past the probe timeout: the queue is saturated and
            // further SYNs are being dropped, which is exactly the state we need
            // for a subsequent connect to time out.
            Err(_elapsed) => {
                saturated = true;
                break;
            }
            // An immediate connect error means the queue is *not* saturated
            // (e.g. the connection was refused). Failing here rather than
            // proceeding keeps the test deterministic and surfaces the real
            // cause instead of a confusing downstream failure.
            Ok(Err(e)) => panic!("unexpected error while filling accept queue: {e}"),
        }
    }
    assert!(
        saturated,
        "accept queue never saturated after {} connects; cannot exercise the connect timeout",
        blockers.len()
    );

    SaturatedTcpListener {
        addr,
        _listener: listener,
        _blockers: blockers,
    }
}
