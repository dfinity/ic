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
            JobType::Replica => write!(f, "replica"),
            JobType::NodeExporter(NodeOS::Guest) => write!(f, "node_exporter"),
            JobType::NodeExporter(NodeOS::Host) => write!(f, "host_node_exporter"),
            JobType::Orchestrator => write!(f, "orchestrator"),
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
