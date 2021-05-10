use super::types::*;
use ic_interfaces::{
    artifact_pool::UnvalidatedArtifact, certification::MutableCertificationPool,
    consensus_pool::MutableConsensusPool, dkg::MutableDkgPool, time_source::TimeSource,
};
use ic_logger::{trace, ReplicaLogger};
use ic_test_utilities::types::ids::node_test_id;
use ic_types::time::Time;
use rand::seq::SliceRandom;
use std::time::Duration;

fn execute_instance<'a, 'b>(
    instance: &'b ConsensusInstance<'a>,
    time_source: &dyn TimeSource,
    logger: &ReplicaLogger,
) -> Option<Time> {
    let mut in_queue = instance.in_queue.borrow_mut();
    let mut out_queue = instance.out_queue.borrow_mut();
    if let Some(inp) = in_queue.pop() {
        trace!(
            logger,
            "Execute instance {} in({}), out({}): {:?}",
            instance.deps.replica_config.node_id,
            in_queue.len(),
            out_queue.len(),
            inp,
        );
        // Update instance timestamp by adding a unit time to input message's time.
        let time_step = Duration::from_millis(UNIT_TIME_STEP);
        let timestamp = inp.timestamp() + time_step;
        instance.clock.replace(timestamp);
        // Move message into pool.
        match inp {
            Input::Message(x) => match x.message {
                InputMessage::Consensus(msg) => {
                    let mut pool = instance.driver.consensus_pool.write().unwrap();
                    pool.insert(UnvalidatedArtifact {
                        message: msg,
                        peer_id: node_test_id(0),
                        timestamp,
                    });
                }
                InputMessage::Dkg(msg) => {
                    let mut dkg_pool = instance.driver.dkg_pool.write().unwrap();
                    dkg_pool.insert(UnvalidatedArtifact {
                        message: msg,
                        peer_id: node_test_id(0),
                        timestamp,
                    });
                }
                InputMessage::Certification(msg) => {
                    let mut pool = instance.driver.certification_pool.write().unwrap();
                    pool.insert(msg);
                }
            },
            // Repeat the polling
            Input::TimerExpired(x) => in_queue.push(Input::TimerExpired(
                x + Duration::from_millis(POLLING_INTERVAL),
            )),
        }
        // Move new messages into out_queue.
        for message in instance.driver.step(time_source) {
            out_queue.push(Message { message, timestamp })
        }
        Some(timestamp)
    } else {
        None
    }
}

/// Always choose an instance i with an input queue that contains the least
/// timestamp(min(i)) value globally. This ensures that all input messages are
/// always executed in order, for all nodes.
#[derive(Debug)]
pub struct GlobalMessage;

impl GlobalMessage {
    pub fn new() -> Box<GlobalMessage> {
        Box::new(GlobalMessage)
    }
}

impl ExecutionStrategy for GlobalMessage {
    fn execute_next(&self, runner: &dyn ConsensusInstances<'_>) -> Option<Time> {
        let logger = runner.logger();
        runner
            .instances()
            .iter()
            .min_by(|i, j| {
                let t_i = i.in_queue.borrow().peek().map(|x| x.timestamp());
                let t_j = j.in_queue.borrow().peek().map(|x| x.timestamp());
                compare_timestamp(t_i, t_j)
            })
            .and_then(|instance| execute_instance(instance, runner.time_source(), logger))
    }
}

#[derive(Debug)]
pub struct RandomExecute;

impl RandomExecute {
    pub fn new() -> Box<RandomExecute> {
        Box::new(RandomExecute)
    }
}

impl ExecutionStrategy for RandomExecute {
    fn execute_next(&self, runner: &dyn ConsensusInstances<'_>) -> Option<Time> {
        let logger = runner.logger();
        let mut instances: Vec<_> = runner.instances().iter().collect();
        let mut rng = runner.rng();
        instances.shuffle(&mut *rng);
        while let Some(instance) = instances.pop() {
            let result = execute_instance(instance, runner.time_source(), logger);
            if result.is_some() {
                return result;
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct GlobalClock;

impl GlobalClock {
    pub fn new() -> Box<GlobalClock> {
        Box::new(GlobalClock)
    }
}

impl ExecutionStrategy for GlobalClock {
    fn execute_next(&self, runner: &dyn ConsensusInstances<'_>) -> Option<Time> {
        let logger = runner.logger();
        runner
            .instances()
            .iter()
            .min_by(|i, j| {
                let t_i = i.in_queue.borrow().peek().map(|_| *i.clock.borrow());
                let t_j = j.in_queue.borrow().peek().map(|_| *j.clock.borrow());
                compare_timestamp(t_i, t_j)
            })
            .and_then(|instance| execute_instance(instance, runner.time_source(), logger))
    }
}
