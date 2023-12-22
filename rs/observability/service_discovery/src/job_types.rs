use std::{collections::HashMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NodeOS {
    Guest,
    Host,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, PartialOrd, Ord, Serialize, Deserialize)]
pub enum JobType {
    Replica,
    NodeExporter(NodeOS),
    Orchestrator,
    MetricsProxy,
}

// The type of discovered job.
impl JobType {
    pub fn port(&self) -> u16 {
        match self {
            Self::Replica => 9090,
            Self::NodeExporter(NodeOS::Host) => 9100,
            Self::NodeExporter(NodeOS::Guest) => 9100,
            Self::Orchestrator => 9091,
            Self::MetricsProxy => 19100,
        }
    }
    pub fn endpoint(&self) -> &'static str {
        match self {
            Self::Replica => "/",
            Self::NodeExporter(NodeOS::Host) => "/metrics",
            Self::NodeExporter(NodeOS::Guest) => "/metrics",
            Self::Orchestrator => "/",
            Self::MetricsProxy => "/metrics",
        }
    }
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::Replica => "http",
            Self::NodeExporter(NodeOS::Host) => "https",
            Self::NodeExporter(NodeOS::Guest) => "https",
            Self::Orchestrator => "http",
            Self::MetricsProxy => "https",
        }
    }
}

#[derive(Debug)]
pub struct JobTypeParseError {
    input: String,
}
impl std::error::Error for JobTypeParseError {}

impl fmt::Display for JobTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not parse {} into a job type", self.input)
    }
}

impl FromStr for JobType {
    type Err = JobTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "replica" => Ok(JobType::Replica),
            "node_exporter" => Ok(JobType::NodeExporter(NodeOS::Guest)),
            "host_node_exporter" => Ok(JobType::NodeExporter(NodeOS::Host)),
            "orchestrator" => Ok(JobType::Orchestrator),
            "metrics-proxy" => Ok(JobType::MetricsProxy),
            _ => Err(JobTypeParseError {
                input: s.to_string(),
            }),
        }
    }
}

impl From<String> for JobType {
    fn from(value: String) -> Self {
        match JobType::from_str(&value) {
            Ok(val) => val,
            Err(_) => panic!("Couldn't parse JobType"),
        }
    }
}

impl fmt::Display for JobType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // When a new job type is added, please do not forget to
            // update its antipode method at from_str() above.
            JobType::Replica => write!(f, "replica"),
            JobType::NodeExporter(NodeOS::Guest) => write!(f, "node_exporter"),
            JobType::NodeExporter(NodeOS::Host) => write!(f, "host_node_exporter"),
            JobType::Orchestrator => write!(f, "orchestrator"),
            JobType::MetricsProxy => write!(f, "metrics-proxy"),
        }
    }
}

#[derive(Clone)]
pub struct JobAndPort {
    pub job_type: JobType,
    pub port: u16,
}

impl FromStr for JobAndPort {
    type Err = JobTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let elements = s.split(':').collect::<Vec<&str>>();

        Ok(JobAndPort {
            job_type: elements.first().unwrap().to_string().into(),
            port: elements.get(1).unwrap().parse().unwrap(),
        })
    }
}

/// This is duplicated in impl Job.
impl JobAndPort {
    pub fn all() -> Vec<Self> {
        [
            JobAndPort {
                job_type: JobType::Replica,
                port: JobType::Replica.port(),
            },
            JobAndPort {
                job_type: JobType::Orchestrator,
                port: JobType::Orchestrator.port(),
            },
            JobAndPort {
                job_type: JobType::NodeExporter(NodeOS::Guest),
                port: JobType::NodeExporter(NodeOS::Guest).port(),
            },
            JobAndPort {
                job_type: JobType::NodeExporter(NodeOS::Host),
                port: JobType::NodeExporter(NodeOS::Host).port(),
            },
            JobAndPort {
                job_type: JobType::MetricsProxy,
                port: JobType::MetricsProxy.port(),
            },
        ]
        .into_iter()
        .collect::<Vec<Self>>()
    }
}

impl fmt::Debug for JobAndPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}, {}>", self.job_type, self.port)
    }
}

pub fn map_jobs(jobs_and_ports: &[JobAndPort]) -> HashMap<JobType, u16> {
    jobs_and_ports
        .iter()
        .map(|job| (job.job_type, job.port))
        .collect()
}
