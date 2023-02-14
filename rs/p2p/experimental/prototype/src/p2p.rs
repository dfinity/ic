use crate::{P2PChangeSet, PoolProcessorHandle, UnvalidatedPoolEvent};
use ic_types::artifact::{ArtifactKind, PriorityFn};
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    oneshot, watch,
};

#[allow(dead_code)]
pub struct P2P<A: ArtifactKind> {
    client_jh: std::thread::JoinHandle<()>,
    send_side: P2PSendSide<A>,
    recv_side: P2PRecvSide<A>,
}

impl<A: ArtifactKind> Drop for P2P<A> {
    fn drop(&mut self) {
        // todo figure out the graceful shutdown of the pool processor and P2P
    }
}

#[allow(dead_code)]
struct P2PSendSide<A: ArtifactKind> {
    // receive
    change_set_rx: Receiver<oneshot::Receiver<P2PChangeSet<A::Message>>>,
    filter_watcher: watch::Receiver<A::Filter>,
}

#[allow(dead_code)]
struct P2PRecvSide<A: ArtifactKind> {
    change_set_tx: Sender<oneshot::Receiver<P2PChangeSet<A::Message>>>,
    priority_fn_watcher: watch::Receiver<PriorityFn<A::Id, A::Attribute>>,
    client_sender: Sender<UnvalidatedPoolEvent<A::Message>>,
}

impl<A: ArtifactKind> P2P<A> {
    pub(crate) fn new(pool_processor_handle: PoolProcessorHandle<A>) -> Self {
        let PoolProcessorHandle::<A> {
            sender,
            priority_fn_watcher,
            filter_watcher,
            jh,
        } = pool_processor_handle;

        let (change_set_tx, change_set_rx) = channel(100);

        let send_side = P2PSendSide {
            filter_watcher,
            change_set_rx,
        };
        let recv_side = P2PRecvSide {
            client_sender: sender,
            priority_fn_watcher,
            change_set_tx,
        };

        Self {
            client_jh: jh,
            send_side,
            recv_side,
        }
    }
}
