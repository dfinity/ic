use std::time::{Duration, Instant};

use anyhow::Error;
use async_trait::async_trait;
use ic_registry_client::client::RegistryClientImpl;

use crate::{registry::CreateRegistryClient, Check};

pub struct WithRetry<T>(
    pub T,
    pub u32,      // max_attempts
    pub Duration, // attempt_interval
);

#[async_trait]
impl<T: CreateRegistryClient> CreateRegistryClient for WithRetry<T> {
    async fn create_registry_client(&mut self) -> Result<RegistryClientImpl, Error> {
        let mut remaining_attempts = self.1;
        let attempt_interval = self.2;

        loop {
            let start_time = Instant::now();

            let out = self.0.create_registry_client().await;
            if out.is_ok() {
                return out;
            }

            remaining_attempts -= 1;
            if remaining_attempts == 0 {
                return out;
            }

            let duration = start_time.elapsed();
            if duration < attempt_interval {
                tokio::time::sleep(attempt_interval - duration).await;
            }
        }
    }
}

#[async_trait]
impl<T: Check> Check for WithRetry<T> {
    async fn check(&self, addr: &str) -> Result<(), Error> {
        let mut remaining_attempts = self.1;
        let attempt_interval = self.2;

        loop {
            let start_time = Instant::now();

            let out = self.0.check(addr).await;
            if out.is_ok() {
                return out;
            }

            remaining_attempts -= 1;
            if remaining_attempts == 0 {
                return out;
            }

            let duration = start_time.elapsed();
            if duration < attempt_interval {
                tokio::time::sleep(attempt_interval - duration).await;
            }
        }
    }
}
