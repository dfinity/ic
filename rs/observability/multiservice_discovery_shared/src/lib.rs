use std::collections::HashMap;

use service_discovery::{
    job_types::{JobType, NodeOS},
    jobs::Job,
};

pub mod builders;
pub mod contracts;
pub mod filters;

pub const JOB_REPLICA: Job = Job {
    _type: JobType::Replica,
    port: 9090,
    endpoint: "/",
    scheme: "http",
};

pub const JOB_NODE_EXPORTER_GUEST: Job = Job {
    _type: JobType::NodeExporter(NodeOS::Guest),
    port: 9100,
    endpoint: "/metrics",
    scheme: "https",
};

pub const JOB_NODE_EXPORTER_HOST: Job = Job {
    _type: JobType::NodeExporter(NodeOS::Host),
    port: 9100,
    endpoint: "/metrics",
    scheme: "https",
};

pub const JOB_ORCHESTRATOR: Job = Job {
    _type: JobType::Orchestrator,
    port: 9091,
    endpoint: "/",
    scheme: "http",
};

pub fn jobs_list() -> Vec<Job> {
    vec![
        JOB_NODE_EXPORTER_GUEST,
        JOB_NODE_EXPORTER_HOST,
        JOB_ORCHESTRATOR,
        JOB_REPLICA,
    ]
}

pub fn get_jobs() -> HashMap<JobType, u16> {
    jobs_list()
        .iter()
        .map(|job| (job._type, job.port))
        .collect()
}
