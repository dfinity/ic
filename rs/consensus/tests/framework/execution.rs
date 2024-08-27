use super::types::*;
use ic_consensus::consensus::bounds::validated_pool_within_bounds;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::p2p::consensus::{BouncerValue, MutablePool, UnvalidatedArtifact};
use ic_logger::{trace, ReplicaLogger};
use ic_test_utilities_types::ids::node_test_id;
use ic_types::time::Time;
use rand::seq::SliceRandom;
use std::time::Duration;

fn execute_instance(
    instance: &ConsensusInstance,
    use_priority_fn: bool,
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
                    if use_priority_fn {
                        match instance
                            .driver
                            .consensus_priority
                            .borrow()
                            .get_priority(&msg)
                        {
                            BouncerValue::Unwanted => return Some(timestamp),
                            BouncerValue::MaybeWantsLater => {
                                instance
                                    .buffered
                                    .borrow_mut()
                                    .push(InputMessage::Consensus(msg));
                                return Some(timestamp);
                            }
                            BouncerValue::Wants => (),
                        };
                    }
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
                        message: *msg,
                        peer_id: node_test_id(0),
                        timestamp,
                    });
                }
                InputMessage::Certification(msg) => {
                    let mut pool = instance.driver.certification_pool.write().unwrap();
                    pool.insert(UnvalidatedArtifact {
                        message: msg,
                        peer_id: node_test_id(0),
                        timestamp,
                    });
                }
                InputMessage::IDkg(msg) => {
                    let mut idkg_pool = instance.driver.idkg_pool.write().unwrap();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message: msg,
                        peer_id: node_test_id(0),
                        timestamp,
                    });
                }
            },
            // Repeat the polling
            Input::TimerExpired(x) => {
                if use_priority_fn {
                    let mut priority = instance.driver.consensus_priority.borrow_mut();
                    if priority.last_updated + PRIORITY_FN_REFRESH_INTERVAL < timestamp {
                        priority.refresh(
                            &instance.driver.consensus_gossip,
                            &*instance.driver.consensus_pool.read().unwrap(),
                            timestamp,
                        );
                    }
                    let mut buffered = instance.buffered.borrow_mut();
                    for message in buffered.drain(..) {
                        in_queue.push(Input::Message(Message { message, timestamp }));
                    }
                }
                in_queue.push(Input::TimerExpired(
                    x + Duration::from_millis(POLLING_INTERVAL),
                ));
            }
        }
        // Move new messages into out_queue.
        for message in instance.driver.step() {
            out_queue.push(Message { message, timestamp })
        }

        // Assert that instance has not crossed their validated pool bounds.
        let pool = instance.deps.consensus_pool.read().unwrap();
        let pool_reader = PoolReader::new(&*pool);
        let cfg = &instance.deps.replica_config;
        let registry_client = instance.deps.registry_client.as_ref();
        if let Some(excess) = validated_pool_within_bounds(&pool_reader, registry_client, cfg) {
            // There are multiple reasons for why this could panic:
            // - You introduced or triggered a regression/bug in the purging logic.
            // - The consensus bounds are outdated, and don't match the implementation.
            //   In this case, consider updating the formulas.
            // - A malicious behavior deviates from the honest replicas, by keeping
            //   too many artifacts in its pool. If this is intentional, consider
            //   excluding malicious nodes from this check.
            panic!(
                "violated consensus pool bounds! too many artifacts in validated pool. \
                    Excess counts:\n--\nExpected:  {:?}\n--\nFound:     {:?}\n--\n",
                excess.expected, excess.found,
            );
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
pub struct GlobalMessage {
    use_priority_fn: bool,
}

impl GlobalMessage {
    pub fn new(use_priority_fn: bool) -> Box<GlobalMessage> {
        Box::new(GlobalMessage { use_priority_fn })
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
            .and_then(|instance| execute_instance(instance, self.use_priority_fn, logger))
    }
}

#[derive(Debug)]
pub struct RandomExecute {
    use_priority_fn: bool,
}

impl RandomExecute {
    pub fn new(use_priority_fn: bool) -> Box<RandomExecute> {
        Box::new(RandomExecute { use_priority_fn })
    }
}

impl ExecutionStrategy for RandomExecute {
    fn execute_next(&self, runner: &dyn ConsensusInstances<'_>) -> Option<Time> {
        let logger = runner.logger();
        let mut instances: Vec<_> = runner.instances().iter().collect();
        let mut rng = runner.rng();
        instances.shuffle(&mut *rng);
        while let Some(instance) = instances.pop() {
            let result = execute_instance(instance, self.use_priority_fn, logger);
            if result.is_some() {
                return result;
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct GlobalClock {
    use_priority_fn: bool,
}

impl GlobalClock {
    pub fn new(use_priority_fn: bool) -> Box<GlobalClock> {
        Box::new(GlobalClock { use_priority_fn })
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
            .and_then(|instance| execute_instance(instance, self.use_priority_fn, logger))
    }
}
