use crate::job_types::JobType;
use crate::job_types::NodeOS;

#[derive(Clone)]
pub struct Job {
    pub _type: JobType,
    pub port: u16,
    pub endpoint: &'static str,
    pub scheme: &'static str,
}

impl From<JobType> for Job {
    fn from(value: JobType) -> Self {
        Job {
            _type: value,
            port: value.port(),
            endpoint: value.endpoint(),
            scheme: value.scheme(),
        }
    }
}

/// This is duplicated in impl JobAndPort.
impl Job {
    pub fn all() -> Vec<Self> {
        vec![
            Job::from(JobType::NodeExporter(NodeOS::Guest)),
            Job::from(JobType::NodeExporter(NodeOS::Host)),
            Job::from(JobType::Orchestrator),
            Job::from(JobType::Replica),
            Job::from(JobType::MetricsProxy),
        ]
    }
}
