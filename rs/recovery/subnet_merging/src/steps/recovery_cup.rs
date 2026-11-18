//! Retry protection for recovery CUP proposals. A second DKG at the same
//! height would replace the subnet's key without restarting its replicas.

use super::check_time_is_past_halting_times;
use ic_base_types::SubnetId;
use ic_protobuf::registry::subnet::v1::{
    CatchUpPackageContents, catch_up_package_contents::CupType,
};
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    steps::Step,
};
use ic_types::{Height, Time};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{ErrorKind, Write},
    path::Path,
    time::{Duration, UNIX_EPOCH},
};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(super) struct RecoveryCupProposal {
    pub(super) source_subnet_id: SubnetId,
    pub(super) destination_subnet_id: SubnetId,
    pub(super) height: Height,
    pub(super) state_hash: String,
}

#[derive(Debug, PartialEq)]
pub(super) enum ProposalOutcome {
    AlreadyExecuted,
    Submitted,
    Pending,
}

impl RecoveryCupProposal {
    /// Reuse a completed recovery, or submit at most once per working directory.
    /// `prepare` only builds the command and checks its preconditions; the
    /// durable record must precede any call that can submit the proposal.
    pub(super) fn propose<S: Step>(
        &self,
        record: &Path,
        halting_times: &[(SubnetId, Time)],
        read_cup: impl FnOnce() -> RecoveryResult<CatchUpPackageContents>,
        prepare: impl FnOnce() -> RecoveryResult<S>,
    ) -> RecoveryResult<ProposalOutcome> {
        if self.matches_cup(&read_cup()?, halting_times)? {
            return Ok(ProposalOutcome::AlreadyExecuted);
        }
        if self.was_attempted(record)? {
            return Ok(ProposalOutcome::Pending);
        }

        let step = prepare()?;
        let contents =
            serde_json::to_vec_pretty(self).map_err(RecoveryError::SerializationError)?;
        let mut file = match OpenOptions::new().write(true).create_new(true).open(record) {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                // Another invocation may have claimed the submission while we
                // prepared it. Never truncate or overwrite that record.
                self.was_attempted(record)?;
                return Ok(ProposalOutcome::Pending);
            }
            Err(err) => return Err(RecoveryError::file_error(record, err)),
        };
        file.write_all(&contents)
            .and_then(|()| file.sync_all())
            .map_err(|err| RecoveryError::file_error(record, err))?;
        let parent = record.parent().expect("the submission record has a parent");
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|err| RecoveryError::file_error(parent, err))?;

        // Keep the record on every outcome, including a failed command or an
        // interrupted process: governance may already have accepted the proposal.
        step.exec()?;
        Ok(ProposalOutcome::Submitted)
    }

    /// A recovery at this height is immutable for this workflow. A conflicting
    /// or later recovery must be reconciled rather than overwritten. The time
    /// need not equal a fresh wall-clock timestamp, but must be past both CUPs.
    pub(super) fn matches_cup(
        &self,
        cup: &CatchUpPackageContents,
        halting_times: &[(SubnetId, Time)],
    ) -> RecoveryResult<bool> {
        match cup.cup_type.as_ref() {
            Some(CupType::Recovery(args)) if args.height >= self.height.get() => {
                if args.height != self.height.get()
                    || hex::encode(&args.state_hash) != self.state_hash
                {
                    return Err(RecoveryError::ValidationFailed(format!(
                        "Subnet {} already has a recovery CUP at height {} with state hash {}; \
                         refusing to replace it with height {} and state hash {}",
                        self.destination_subnet_id,
                        args.height,
                        hex::encode(&args.state_hash),
                        self.height,
                        self.state_hash,
                    )));
                }
                check_time_is_past_halting_times(
                    UNIX_EPOCH + Duration::from_nanos(args.time),
                    halting_times,
                )?;
                Ok(true)
            }
            Some(_) => Ok(false),
            None => Err(RecoveryError::ValidationFailed(format!(
                "The registry CUP contents for subnet {} have no CUP type",
                self.destination_subnet_id,
            ))),
        }
    }

    fn was_attempted(&self, record: &Path) -> RecoveryResult<bool> {
        let contents = match std::fs::read(record) {
            Ok(contents) => contents,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(RecoveryError::file_error(record, err)),
        };
        let previous: Self = serde_json::from_slice(&contents).map_err(|err| {
            RecoveryError::ValidationFailed(format!(
                "Cannot read recovery CUP submission record {}: {err}. Reconcile the previous \
                 submission in governance before removing this record; it may still execute.",
                record.display(),
            ))
        })?;
        if previous != *self {
            return Err(RecoveryError::ValidationFailed(format!(
                "Recovery CUP submission record {} is for {previous:?}, not {self:?}; \
                 reconcile the previous submission before proceeding",
                record.display(),
            )));
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_base_types::PrincipalId;
    use ic_protobuf::registry::subnet::v1::{GenesisArgs, RecoveryArgs};
    use std::cell::Cell;

    fn proposal() -> RecoveryCupProposal {
        RecoveryCupProposal {
            source_subnet_id: SubnetId::from(PrincipalId::new_subnet_test_id(1)),
            destination_subnet_id: SubnetId::from(PrincipalId::new_subnet_test_id(2)),
            height: Height::new(1000),
            state_hash: hex::encode([42; 32]),
        }
    }

    fn halting_times() -> [(SubnetId, Time); 2] {
        [
            (
                proposal().source_subnet_id,
                Time::from_nanos_since_unix_epoch(100),
            ),
            (
                proposal().destination_subnet_id,
                Time::from_nanos_since_unix_epoch(200),
            ),
        ]
    }

    fn genesis() -> CatchUpPackageContents {
        CatchUpPackageContents {
            cup_type: Some(CupType::Genesis(GenesisArgs {})),
            ..Default::default()
        }
    }

    fn recovery(height: u64, hash: [u8; 32], time: u64) -> CatchUpPackageContents {
        CatchUpPackageContents {
            cup_type: Some(CupType::Recovery(RecoveryArgs {
                height,
                state_hash: hash.to_vec(),
                time,
            })),
            ..Default::default()
        }
    }

    struct Submit<F: Fn() -> RecoveryResult<()>>(F);

    type TestStep = Submit<fn() -> RecoveryResult<()>>;

    impl<F: Fn() -> RecoveryResult<()>> Step for Submit<F> {
        fn descr(&self) -> String {
            "submit test proposal".to_string()
        }

        fn exec(&self) -> RecoveryResult<()> {
            (self.0)()
        }
    }

    #[test]
    fn resume_after_execution_does_not_prepare_or_submit_another_proposal() {
        let tmp = tempfile::tempdir().unwrap();
        let record = tmp.path().join("proposal.json");
        // Also covers a recovery submitted before the tool kept local records.
        let outcome = proposal()
            .propose(
                &record,
                &halting_times(),
                || Ok(recovery(1000, [42; 32], 201)),
                || -> RecoveryResult<TestStep> {
                    panic!("an already executed recovery must not be submitted again")
                },
            )
            .unwrap();
        assert_eq!(outcome, ProposalOutcome::AlreadyExecuted);
        assert!(!record.exists());
    }

    #[test]
    fn retries_and_resumes_reuse_the_attempt_even_after_a_lost_submission_response() {
        for lost_response in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let record = tmp.path().join("proposal.json");
            let submissions = Cell::new(0);
            let outcome = proposal().propose(
                &record,
                &halting_times(),
                || Ok(genesis()),
                || {
                    Ok(Submit(|| {
                        // The record must be complete before the external side effect.
                        assert!(proposal().was_attempted(&record).unwrap());
                        submissions.set(submissions.get() + 1);
                        if lost_response {
                            Err(RecoveryError::UnexpectedError("response lost".to_string()))
                        } else {
                            Ok(())
                        }
                    }))
                },
            );
            if lost_response {
                assert!(outcome.is_err());
            } else {
                assert_eq!(outcome.unwrap(), ProposalOutcome::Submitted);
            }
            let recorded = std::fs::read(&record).unwrap();

            // Fresh objects model a resumed process; the registry can still
            // expose the old CUP while the proposal is pending or running DKG.
            for cup in [genesis(), recovery(1000, [42; 32], 201)] {
                let expected = if cup == genesis() {
                    ProposalOutcome::Pending
                } else {
                    ProposalOutcome::AlreadyExecuted
                };
                let outcome = proposal()
                    .propose(
                        &record,
                        &halting_times(),
                        || Ok(cup),
                        || {
                            Ok(Submit(|| {
                                submissions.set(submissions.get() + 1);
                                Ok(())
                            }))
                        },
                    )
                    .unwrap();
                assert_eq!(outcome, expected);
                assert_eq!(submissions.get(), 1);
                assert_eq!(std::fs::read(&record).unwrap(), recorded);
            }
        }
    }

    #[test]
    fn invalid_or_conflicting_registry_cups_cannot_be_overwritten() {
        assert!(
            !proposal()
                .matches_cup(&genesis(), &halting_times())
                .unwrap()
        );
        assert!(
            !proposal()
                .matches_cup(&recovery(999, [1; 32], 50), &halting_times())
                .unwrap()
        );
        for cup in [
            recovery(1000, [1; 32], 201),
            recovery(1001, [42; 32], 201),
            recovery(1000, [42; 32], 100),
            recovery(1000, [42; 32], 200),
            CatchUpPackageContents::default(),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let record = tmp.path().join("proposal.json");
            assert!(
                proposal()
                    .propose(
                        &record,
                        &halting_times(),
                        || Ok(cup),
                        || -> RecoveryResult<TestStep> {
                            panic!("a conflicting recovery must not be overwritten")
                        },
                    )
                    .is_err()
            );
            assert!(!record.exists());
        }
    }

    #[test]
    fn unreadable_or_conflicting_submission_records_block_new_submissions() {
        let tmp = tempfile::tempdir().unwrap();
        let record = tmp.path().join("proposal.json");
        let mut other = proposal();
        other.destination_subnet_id = other.source_subnet_id;
        for contents in [
            vec![],
            b"{\"height\":".to_vec(),
            serde_json::to_vec(&other).unwrap(),
        ] {
            std::fs::write(&record, &contents).unwrap();
            assert!(
                proposal()
                    .propose(
                        &record,
                        &halting_times(),
                        || Ok(genesis()),
                        || -> RecoveryResult<TestStep> {
                            panic!("an uncertain previous submission must not be repeated")
                        },
                    )
                    .is_err()
            );
            assert_eq!(std::fs::read(&record).unwrap(), contents);
        }
    }

    #[test]
    fn failed_preparation_does_not_record_a_submission_attempt() {
        let tmp = tempfile::tempdir().unwrap();
        let record = tmp.path().join("proposal.json");
        assert!(
            proposal()
                .propose(
                    &record,
                    &halting_times(),
                    || Ok(genesis()),
                    || -> RecoveryResult<TestStep> {
                        Err(RecoveryError::ValidationFailed(
                            "clock is behind".to_string(),
                        ))
                    },
                )
                .is_err()
        );
        assert!(!record.exists());
    }

    #[test]
    fn a_submission_record_created_during_preparation_is_not_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let record = tmp.path().join("proposal.json");
        let outcome = proposal()
            .propose(
                &record,
                &halting_times(),
                || Ok(genesis()),
                || {
                    std::fs::write(&record, serde_json::to_vec(&proposal()).unwrap()).unwrap();
                    Ok(Submit(|| {
                        panic!("another invocation already claimed the submission")
                    }))
                },
            )
            .unwrap();
        assert_eq!(outcome, ProposalOutcome::Pending);
    }
}
