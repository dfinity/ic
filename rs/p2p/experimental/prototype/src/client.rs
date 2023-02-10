use crate::*;
use ic_interfaces::{
    artifact_pool::UnvalidatedArtifact,
    consensus::{Consensus, ConsensusGossip},
    consensus_pool::MutableConsensusPool,
    time_source::TimeSource,
};
use ic_types::artifact::{ArtifactKind, PriorityFn};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{channel, Receiver};

const STAGGERED_PRIORITY_DURATION: Duration = Duration::from_secs(30);

struct PoolProcessor<A: ArtifactKind, P: MutableConsensusPool> {
    pool: P,
    mutation_source: Box<dyn Consensus + Send + Sync>,
    priority_source: Box<dyn ConsensusGossip + Send + Sync>,
    time_source: Arc<dyn TimeSource>,
    receiver: Receiver<UnvalidatedPoolEvent<A::Message>>,
    priority_fn_sender: watch::Sender<PriorityFn<A::Id, A::Attribute>>,
    last_priority_update: Instant,
}

type ConsensusPoolProcessor<P> = PoolProcessor<ConsensusArtifact, P>;

impl<P: MutableConsensusPool> ConsensusPoolProcessor<P> {
    fn new(
        pool: P,
        mutation_source: Box<dyn Consensus + Send + Sync>,
        priority_source: Box<dyn ConsensusGossip + Send + Sync>,
        time_source: Arc<dyn TimeSource>,
        receiver: Receiver<UnvalidatedPoolEvent<ConsensusMessage>>,
        priority_fn_sender: watch::Sender<
            PriorityFn<ConsensusMessageId, ConsensusMessageAttribute>,
        >,
    ) -> Self {
        Self {
            receiver,
            pool,
            mutation_source,
            priority_source,
            time_source,
            last_priority_update: Instant::now(),
            priority_fn_sender,
        }
    }

    fn update_pools(
        &mut self,
        _artifacts: Vec<UnvalidatedArtifact<ConsensusMessage>>,
    ) -> P2PChangeSet<ConsensusMessage> {
        // add artifacts to unvalidated pool
        let change_set = self.mutation_source.on_state_change(&self.pool);
        self.pool
            .apply_changes(self.time_source.as_ref(), change_set);
        // apply change set to pools and construct P2PChangeSet
        P2PChangeSet::new()
    }

    fn run(&mut self) {
        while let Some(event) = self.receiver.blocking_recv() {
            // do we immediately execute again if the state changed ?

            let (sender, p2p_change_set) = match event {
                UnvalidatedPoolEvent::Tick(sender) => (sender, self.update_pools(vec![])),
                UnvalidatedPoolEvent::Artifacts((artifacts, sender)) => {
                    (sender, self.update_pools(artifacts))
                }
                UnvalidatedPoolEvent::Bootstrap(sender) => {
                    // get all validated artifacts and construct the p2p change set from them
                    (sender, P2PChangeSet::new())
                }
            };
            // We do a staggered updated of priorities. There is no point in having separate channel for updating the priority function
            // anyways we wanted to update the priority function on each on_stage_change call.
            if self.last_priority_update.elapsed() > STAGGERED_PRIORITY_DURATION {
                self.last_priority_update = Instant::now();
                // TODO: think about the failure here, we should either exit the loop or just log error
                // if this happens maybe we are already shutting down
                let _ = self
                    .priority_fn_sender
                    .send(self.priority_source.get_priority_function(&self.pool));
            }
            // TODO: think about the failure here, we should either exit the loop or just log error
            // if this happens maybe we are already shutting down
            let _ = sender.send(p2p_change_set);
        }
    }
}

impl ConsensusPoolProcessorHandle {
    pub(crate) fn new<P: MutableConsensusPool + Send + Sync + 'static>(
        pool: P,
        mutation_source: Box<dyn Consensus + Send + Sync>,
        priority_source: Box<dyn ConsensusGossip + Send + Sync>,
        time_source: Arc<dyn TimeSource>,
    ) -> Self {
        let (sender, receiver) = channel(8);

        let (priority_fn_sender, priority_fn_watcher) =
            watch::channel(priority_source.get_priority_function(&pool));

        let mut client = ConsensusPoolProcessor::new(
            pool,
            mutation_source,
            priority_source,
            time_source,
            receiver,
            priority_fn_sender,
        );

        // exists when the sender/client handle is dropped
        let jh = std::thread::spawn(move || {
            client.run();
        });

        Self {
            sender,
            jh,
            priority_fn_watcher,
        }
    }
}
