use std::{fmt, str::FromStr};

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum NodeOS {
    Guest,
    Host,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
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
