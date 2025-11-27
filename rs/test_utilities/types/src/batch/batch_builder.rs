use ic_types::{
    Height, Randomness, RegistryVersion, ReplicaVersion, Time,
    batch::{Batch, BatchContent, BatchMessages, BlockmakerMetrics},
    time::UNIX_EPOCH,
};

pub struct BatchBuilder {
    batch: Batch,
}

impl Default for BatchBuilder {
    /// Create a default, empty, XNetPayload
    fn default() -> Self {
        Self {
            batch: Batch {
                batch_number: Height::from(0),
                batch_summary: None,
                requires_full_state_hash: false,
                content: BatchContent::Data {
                    batch_messages: BatchMessages::default(),
                    chain_key_data: Default::default(),
                    consensus_responses: vec![],
                },
                randomness: Randomness::from([0; 32]),
                registry_version: RegistryVersion::from(1),
                time: UNIX_EPOCH,
                blockmaker_metrics: BlockmakerMetrics::new_for_test(),
                replica_version: ReplicaVersion::default(),
            },
        }
    }
}

impl BatchBuilder {
    /// Creates a new `BatchBuilder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the `batch_number` field.
    pub fn batch_number(mut self, batch_number: Height) -> Self {
        self.batch.batch_number = batch_number;
        self
    }

    /// Sets the `messages` field.
    pub fn messages(mut self, messages: BatchMessages) -> Self {
        self.batch.content = BatchContent::Data {
            batch_messages: messages,
            chain_key_data: Default::default(),
            consensus_responses: vec![],
        };
        self
    }

    /// Sets the `randomness` field.
    pub fn randomness(mut self, randomness: Randomness) -> Self {
        self.batch.randomness = randomness;
        self
    }

    /// Sets the `registry_version` field.
    pub fn registry_version(mut self, registry_version: RegistryVersion) -> Self {
        self.batch.registry_version = registry_version;
        self
    }

    /// Sets the `time` field.
    pub fn time(mut self, time: Time) -> Self {
        self.batch.time = time;
        self
    }

    /// Returns the built `Batch`.
    pub fn build(&self) -> Batch {
        self.batch.clone()
    }
}
