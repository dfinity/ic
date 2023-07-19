/// Channel based transport that implements the transport trait
/// This crate is intended for testing purposes.
///
/// It tries to model a real network by having links with
/// a specified capacity and latency.
///
/// The network is model in a star topology with a infinite
/// capacity router in the middle.
/// Each node has a symmetrical connection to the router
/// with an associated link latency and capacity.
///
/// Example:
///
/// Send 2Mb message from top left to bottom right:
///     - Acquire 2Mb capacity for top left up link
///     - Wait 10ms
///     - Acquire 2Mb capacity for bottom right down link
///     - Wait 50ms
///
/// The steps described above are performed by the router.
///
///
/// ┌──────┐                           ┌──────┐
/// │ Node ├───┐                  ┌────┤ Node │
/// └──────┘   │                  │    └──────┘
///            │                  │
///   lat:10ms │                  │ lat:20ms
///   cap:6Mb  │    ┌────────┐    │ cap:5Mb
///            ├────┤ Router ├────┤
///            │    └────────┘    │
///   lat:30ms │                  │ lat:50ms
///   cap:3Mb  │                  │ cap:9Mb
/// ┌──────┐   │                  │    ┌──────┐
/// │ Node ├───┘                  └────┤ Node │
/// └──────┘                           └──────┘
use async_trait::async_trait;
use axum::{
    body::{Body, HttpBody},
    Router,
};
use bytes::{Buf, BufMut, Bytes};
use http::{Request, Response};
use ic_quic_transport::{Transport, TransportError};
use ic_types::NodeId;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    select,
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        oneshot, Semaphore,
    },
};
use tower::{Service, ServiceExt};

#[derive(Clone)]
pub struct PeerHandle {
    rpc_tx: UnboundedSender<(Request<Bytes>, oneshot::Sender<Response<Bytes>>)>,
    latency: Duration,
    up_capacity: Arc<Semaphore>,
    down_capacity: Arc<Semaphore>,
}

impl PeerHandle {
    pub fn new(
        rpc_tx: UnboundedSender<(Request<Bytes>, oneshot::Sender<Response<Bytes>>)>,
        latency: Duration,
        capacity: usize,
    ) -> Self {
        Self {
            rpc_tx,
            latency,
            up_capacity: Arc::new(Semaphore::new(capacity)),
            down_capacity: Arc::new(Semaphore::new(capacity)),
        }
    }
}

impl Default for TransportRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct TransportRouter {
    peers: Arc<RwLock<HashMap<NodeId, PeerHandle>>>,
    router_req_tx: UnboundedSender<(Request<Bytes>, NodeId, oneshot::Sender<Response<Bytes>>)>,
    router_resp_tx: UnboundedSender<(Response<Bytes>, NodeId, oneshot::Sender<Response<Bytes>>)>,
}

impl TransportRouter {
    pub fn new() -> Self {
        let (router_req_tx, mut router_req_rx) =
            unbounded_channel::<(Request<Bytes>, NodeId, oneshot::Sender<Response<Bytes>>)>();
        let (router_resp_tx, mut router_resp_rx) =
            unbounded_channel::<(Response<Bytes>, NodeId, oneshot::Sender<Response<Bytes>>)>();
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peers_c = peers.clone();
        // Spawn request router for all requests.
        tokio::spawn(async move {
            loop {
                select! {
                    Some((req,dest,resp)) = router_req_rx.recv() => {
                        Self::handle_incoming_request(peers_c.clone(), req, dest, resp);
                    }
                    Some((req,dest,resp)) = router_resp_rx.recv() => {
                        Self::handle_incoming_response(peers_c.clone(), req, dest, resp);
                    }
                    else => break,
                }
            }
        });

        Self {
            peers,
            router_req_tx,
            router_resp_tx,
        }
    }

    /// Adds peer to the memory transport.
    /// This involves starting an event loop that listens for requests.
    pub fn add_peer(
        &mut self,
        node_id: NodeId,
        mut router: Router,
        latency: Duration,
        capacity: usize,
    ) -> PeerTransport {
        // It is fine to use unbounded channel since ingestion rate is limited by
        // capacity and processing rate >> ingestion rate.
        let (rpc_tx, mut rpc_rx) =
            unbounded_channel::<(Request<Bytes>, oneshot::Sender<Response<Bytes>>)>();
        self.peers
            .write()
            .unwrap()
            .insert(node_id, PeerHandle::new(rpc_tx, latency, capacity));
        let this_node_id = node_id;
        let router_resp_tx = self.router_resp_tx.clone();

        // Spawn request handler for this added node
        tokio::spawn(async move {
            loop {
                select! {
                    Some((msg, oneshot_tx)) = rpc_rx.recv() => {
                        // Get origin NodeId and change request body type
                        let (parts, body) = msg.into_parts();
                        let origin_id = *parts.extensions.get::<NodeId>().unwrap();
                        let req = Request::from_parts(parts, Body::from(body));

                        // Call request handler
                        let resp = router.ready().await.unwrap().call(req).await.unwrap();

                        // Transform request back to `Request<Bytes>` and attach this node in the extension map.
                        let (mut parts, body) = resp.into_parts();
                        let body = to_bytes(body).await.unwrap();
                        parts.extensions.insert(this_node_id );
                        let resp = Response::from_parts(parts, body);
                        let _ = router_resp_tx.send((resp,origin_id,oneshot_tx));
                    }
                }
            }
        });

        PeerTransport {
            node_id,
            router_request_tx: self.router_req_tx.clone(),
            global: self.clone(),
        }
    }

    /// Reserves capacities for the request and waits for the required latency.
    /// After using the requested resources the request is delivered to the peer.
    fn handle_incoming_request(
        peers: Arc<RwLock<HashMap<NodeId, PeerHandle>>>,
        req: Request<Bytes>,
        dest: NodeId,
        resp: oneshot::Sender<Response<Bytes>>,
    ) {
        let request_size = request_size(&req);
        let origin_id = req.extensions().get::<NodeId>().unwrap();
        let peers_g = peers.read().unwrap();
        if !peers_g.contains_key(&dest) || !peers_g.contains_key(origin_id) {
            return;
        }
        let dest_ph = peers_g.get(&dest).unwrap().clone();
        let origin_ph = peers_g.get(origin_id).unwrap().clone();
        drop(peers_g);

        let req_fut = async move {
            let _permit = origin_ph
                .up_capacity
                .acquire_many(request_size as u32)
                .await
                .unwrap();
            tokio::time::sleep(origin_ph.latency).await;
            drop(_permit);
            let _permit = dest_ph
                .down_capacity
                .acquire_many(request_size as u32)
                .await
                .unwrap();
            tokio::time::sleep(dest_ph.latency).await;
            let _ = dest_ph.rpc_tx.send((req, resp));
        };
        tokio::spawn(req_fut);
    }

    /// Reserves capacities for the response and waits for the required latency.
    /// After using the requested resources the response is delivered.
    fn handle_incoming_response(
        peers: Arc<RwLock<HashMap<NodeId, PeerHandle>>>,
        req: Response<Bytes>,
        dest: NodeId,
        resp: oneshot::Sender<Response<Bytes>>,
    ) {
        let response_size = response_size(&req);
        let origin_id = req.extensions().get::<NodeId>().unwrap();
        let peers_g = peers.read().unwrap();
        if !peers_g.contains_key(&dest) || !peers_g.contains_key(origin_id) {
            return;
        }
        let dest_ph = peers_g.get(&dest).unwrap().clone();
        let origin_ph = peers_g.get(origin_id).unwrap().clone();
        drop(peers_g);

        let resp_fut = async move {
            let _permit = origin_ph
                .up_capacity
                .acquire_many(response_size as u32)
                .await
                .unwrap();
            tokio::time::sleep(origin_ph.latency).await;
            drop(_permit);
            let _permit = dest_ph
                .down_capacity
                .acquire_many(response_size as u32)
                .await
                .unwrap();
            tokio::time::sleep(dest_ph.latency).await;
            // Receiver might have already stopped listening, therefore ignore the result.
            let _ = resp.send(req);
        };
        tokio::spawn(resp_fut);
    }
}

#[derive(Clone)]
pub struct PeerTransport {
    node_id: NodeId,
    router_request_tx: UnboundedSender<(Request<Bytes>, NodeId, oneshot::Sender<Response<Bytes>>)>,
    global: TransportRouter,
}

fn request_size(r: &Request<Bytes>) -> usize {
    r.body().len()
        + r.headers()
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum::<usize>()
        + r.uri().path().len()
}

fn response_size(r: &Response<Bytes>) -> usize {
    r.body().len()
        + r.headers()
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum::<usize>()
}

#[async_trait]
impl Transport for PeerTransport {
    async fn rpc(
        &self,
        peer_id: &NodeId,
        mut request: Request<Bytes>,
    ) -> Result<Response<Bytes>, TransportError> {
        if peer_id == &self.node_id {
            return Err(TransportError::Disconnected {
                connection_error: Some("Can't connect to self".to_string()),
            });
        }

        let (oneshot_tx, oneshot_rx) = oneshot::channel();
        request.extensions_mut().insert(self.node_id);
        self.router_request_tx
            .send((request, *peer_id, oneshot_tx))
            .unwrap();
        Ok(oneshot_rx.await.unwrap())
    }

    async fn push(&self, peer_id: &NodeId, request: Request<Bytes>) -> Result<(), TransportError> {
        let _ = self.rpc(peer_id, request).await?;
        Ok(())
    }

    fn peers(&self) -> Vec<NodeId> {
        self.global.peers.read().unwrap().keys().cloned().collect()
    }
}

// Copied from hyper. Used to transform `BoxBodyBytes` to `Bytes`.
// It might look slow but since in our case the data is fully available
// the first data() call will immediately return everything.
pub(crate) async fn to_bytes<T>(body: T) -> Result<Bytes, T::Error>
where
    T: HttpBody + Unpin,
{
    futures::pin_mut!(body);

    // If there's only 1 chunk, we can just return Buf::to_bytes()
    let mut first = if let Some(buf) = body.data().await {
        buf?
    } else {
        return Ok(Bytes::new());
    };

    let second = if let Some(buf) = body.data().await {
        buf?
    } else {
        return Ok(first.copy_to_bytes(first.remaining()));
    };

    // Don't pre-emptively reserve *too* much.
    let rest = (body.size_hint().lower() as usize).min(1024 * 16);
    let cap = first
        .remaining()
        .saturating_add(second.remaining())
        .saturating_add(rest);
    // With more than 1 buf, we gotta flatten into a Vec first.
    let mut vec = Vec::with_capacity(cap);
    vec.put(first);
    vec.put(second);

    while let Some(buf) = body.data().await {
        vec.put(buf?);
    }

    Ok(vec.into())
}
