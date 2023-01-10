use std::{
    any::Any,
    collections::{BTreeSet, HashMap},
};

use erased_serde::serialize_trait_object;
use serde::Serialize;
use service_discovery::{job_types::JobType, TargetGroup};

pub trait VectorConfigBuilder {
    fn build(&self, target_groups: BTreeSet<TargetGroup>, job: JobType) -> VectorConfigEnriched;
}

#[derive(Serialize)]
pub struct VectorConfigEnriched {
    sources: HashMap<String, Box<dyn VectorSource>>,
    transforms: HashMap<String, Box<dyn VectorTransform>>,
}

pub trait VectorSource: erased_serde::Serialize + ToAny {
    fn clone_dyn(&self) -> Box<dyn VectorSource>;
}
pub trait VectorTransform: erased_serde::Serialize + ToAny {
    fn clone_dyn(&self) -> Box<dyn VectorTransform>;
}

impl Clone for Box<dyn VectorSource> {
    fn clone(&self) -> Self {
        self.clone_dyn()
    }
}

impl Clone for Box<dyn VectorTransform> {
    fn clone(&self) -> Self {
        self.clone_dyn()
    }
}

serialize_trait_object!(VectorSource);
serialize_trait_object!(VectorTransform);

impl VectorConfigEnriched {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            transforms: HashMap::new(),
        }
    }

    pub fn add_target_group(
        &mut self,
        key: String,
        source: Box<dyn VectorSource>,
        transform: Box<dyn VectorTransform>,
    ) {
        self.sources.insert(key.clone() + "-source", source);
        self.transforms.insert(key + "-transform", transform);
    }

    pub fn get_sources(&self) -> HashMap<String, Box<dyn VectorSource>> {
        self.sources.clone()
    }

    pub fn get_transforms(&self) -> HashMap<String, Box<dyn VectorTransform>> {
        self.transforms.clone()
    }
}

impl Default for VectorConfigEnriched {
    fn default() -> Self {
        Self::new()
    }
}

pub trait ToAny: 'static {
    fn as_any(&self) -> &dyn Any;
}

impl<T: 'static> ToAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
