use crate::job_types::JobType;

#[derive(Clone)]
pub struct Job {
    pub _type: JobType,
    pub port: u16,
    pub endpoint: &'static str,
    pub scheme: &'static str,
}
