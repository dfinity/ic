use crate::{
    RecoveryResult, app_subnet_recovery, app_subnet_recovery::AppSubnetRecovery,
    error::RecoveryError, nns_recovery_failover_nodes,
    nns_recovery_failover_nodes::NNSRecoveryFailoverNodes, nns_recovery_same_nodes,
    nns_recovery_same_nodes::NNSRecoverySameNodes, steps::Step,
};
use slog::{Logger, info, warn};
use strum::EnumMessage;

use std::{fmt::Debug, iter::Peekable};

pub trait RecoveryIterator<
    StepType: Copy + Debug + PartialEq + EnumMessage,
    I: Iterator<Item = StepType>,
>
{
    fn get_step_iterator(&mut self) -> &mut Peekable<I>;
    fn get_step_impl(&self, step_type: StepType) -> RecoveryResult<Box<dyn Step>>;
    fn store_next_step(&mut self, step_type: Option<StepType>);

    fn interactive(&self) -> bool;
    fn read_step_params(&mut self, step_type: StepType);
    fn get_logger(&self) -> &Logger;

    /// Advances the iterator to the specified step.
    fn resume(&mut self, step: StepType) {
        while let Some(current_step) = self
            .get_step_iterator()
            .next_if(|current_step| *current_step != step)
        {
            info!(
                self.get_logger(),
                "Skipping already executed step {:?}", current_step
            );
            if current_step == step {
                break;
            }
        }
    }

    fn get_skipped_steps(&self) -> Vec<StepType> {
        vec![]
    }

    fn next_step(&mut self) -> Option<(StepType, Box<dyn Step>)> {
        let skipped_steps = self.get_skipped_steps();
        let result = if let Some(current_step) = self.get_step_iterator().next() {
            if skipped_steps.contains(&current_step) {
                self.next_step()
            } else {
                super::cli::print_step(self.get_logger(), &format!("{current_step:?}"));
                if let Some(explanation) = current_step.get_documentation() {
                    info!(self.get_logger(), "\n\n{}\n", explanation);
                }
                if self.interactive() {
                    self.read_step_params(current_step);
                }
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
            }
        } else {
            None
        };

        let next_step = self.get_step_iterator().peek().copied();
        self.store_next_step(next_step);

        result
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Copy, Clone, PartialEq, Debug, EnumMessage)]
    enum FakeStep {
        P0,
        P1,
        P2,
        P3,
        P4,
        P5,
        P6,
        P7,
        P8,
        P9,
    }

    impl Step for FakeStep {
        fn descr(&self) -> String {
            String::from("Fake Step Description")
        }

        fn exec(&self) -> RecoveryResult<()> {
            Ok(())
        }
    }

    /// Fake RecoveryIterator which iterates from 0 to 9.
    struct FakeRecoveryIterator {
        step_iterator: Peekable<Box<std::vec::IntoIter<FakeStep>>>,
        logger: Logger,
        read_step_params_called: bool,
        interactive: bool,
        next_step: Option<FakeStep>,
    }

    impl FakeRecoveryIterator {
        fn new(interactive: bool) -> Self {
            Self {
                step_iterator: Box::new(
                    vec![
                        FakeStep::P0,
                        FakeStep::P1,
                        FakeStep::P2,
                        FakeStep::P3,
                        FakeStep::P4,
                        FakeStep::P5,
                        FakeStep::P6,
                        FakeStep::P7,
                        FakeStep::P8,
                        FakeStep::P9,
                    ]
                    .into_iter(),
                )
                .peekable(),
                logger: crate::util::make_logger(),
                read_step_params_called: false,
                interactive,
                next_step: None,
            }
        }
    }

    impl RecoveryIterator<FakeStep, Box<std::vec::IntoIter<FakeStep>>> for FakeRecoveryIterator {
        fn get_step_iterator(&mut self) -> &mut Peekable<Box<std::vec::IntoIter<FakeStep>>> {
            &mut self.step_iterator
        }

        fn store_next_step(&mut self, next_step: Option<FakeStep>) {
            self.next_step = next_step
        }

        fn get_logger(&self) -> &Logger {
            &self.logger
        }

        fn interactive(&self) -> bool {
            self.interactive
        }

        fn get_step_impl(&self, _step_type: FakeStep) -> RecoveryResult<Box<dyn Step>> {
            Ok(Box::new(FakeStep::P1))
        }
        fn read_step_params(&mut self, _step_type: FakeStep) {
            self.read_step_params_called = true;
        }
    }

    #[test]
    fn resume_advances_to_right_step() {
        let mut fake_recovery_iterator = FakeRecoveryIterator::new(/*interactive=*/ true);

        fake_recovery_iterator.resume(FakeStep::P5);

        assert_eq!(
            fake_recovery_iterator.step_iterator.next(),
            Some(FakeStep::P5)
        );
    }

    #[test]
    fn resume_doesnt_read_step_params() {
        let mut fake_recovery_iterator = FakeRecoveryIterator::new(/*interactive=*/ true);

        fake_recovery_iterator.resume(FakeStep::P5);

        assert!(!fake_recovery_iterator.read_step_params_called);
    }

    #[test]
    fn next_step_stores_next_step() {
        let mut fake_recovery_iterator = FakeRecoveryIterator::new(/*interactive=*/ true);

        fake_recovery_iterator.next_step();
        assert_eq!(Some(FakeStep::P1), fake_recovery_iterator.next_step);

        fake_recovery_iterator.next_step();
        assert_eq!(Some(FakeStep::P2), fake_recovery_iterator.next_step);
    }

    #[test]
    fn next_step_reads_params_only_when_interactive() {
        for &interactive in &[false, true] {
            let mut fake_recovery_iterator = FakeRecoveryIterator::new(interactive);

            fake_recovery_iterator.next_step();

            assert_eq!(fake_recovery_iterator.read_step_params_called, interactive);
        }
    }
}
