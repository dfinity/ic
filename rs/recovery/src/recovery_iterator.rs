use std::fmt::Debug;

use crate::{app_subnet_recovery, nns_recovery_failover_nodes, nns_recovery_same_nodes};
use crate::{
    app_subnet_recovery::AppSubnetRecovery, error::RecoveryError,
    nns_recovery_failover_nodes::NNSRecoveryFailoverNodes,
    nns_recovery_same_nodes::NNSRecoverySameNodes, steps::Step, RecoveryResult,
};
use slog::{info, warn, Logger};

pub trait RecoveryIterator<T: Copy + Debug> {
    fn get_step_iterator(&mut self) -> &mut Box<dyn Iterator<Item = T>>;
    fn get_step_impl(&self, step_type: T) -> RecoveryResult<Box<dyn Step>>;
    fn get_logger(&self) -> &Logger;

    fn next_step(&mut self) -> Option<(T, Box<dyn Step>)> {
        if let Some(current_step) = self.get_step_iterator().next() {
            match self.get_step_impl(current_step) {
                Ok(step) => Some((current_step, step)),
                Err(RecoveryError::StepSkipped) => {
                    info!(self.get_logger(), "Skipping step {:?}", current_step);
                    self.next_step()
                }
                Err(e) => {
                    warn!(
                        self.get_logger(),
                        "Step generation of {:?} failed: {}", current_step, e
                    );
                    warn!(self.get_logger(), "Skipping step...");
                    self.next_step()
                }
            }
        } else {
            None
        }
    }
}

impl Iterator for AppSubnetRecovery {
    type Item = (app_subnet_recovery::StepType, Box<dyn Step>);
    fn next(&mut self) -> Option<Self::Item> {
        self.next_step()
    }
}

impl Iterator for NNSRecoverySameNodes {
    type Item = (nns_recovery_same_nodes::StepType, Box<dyn Step>);
    fn next(&mut self) -> Option<Self::Item> {
        self.next_step()
    }
}

impl Iterator for NNSRecoveryFailoverNodes {
    type Item = (nns_recovery_failover_nodes::StepType, Box<dyn Step>);
    fn next(&mut self) -> Option<Self::Item> {
        self.next_step()
    }
}
