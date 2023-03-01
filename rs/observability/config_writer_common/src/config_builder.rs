use std::collections::BTreeSet;
use std::fmt::Debug;

use service_discovery::{jobs::Job, TargetGroup};

pub trait Config: erased_serde::Serialize + Debug {
    fn updated(&self) -> bool;
    fn name(&self) -> String;
}
erased_serde::serialize_trait_object!(Config);

pub trait ConfigBuilder {
    fn build(&mut self, target_groups: BTreeSet<TargetGroup>, job: Job) -> Box<dyn Config>;
}
