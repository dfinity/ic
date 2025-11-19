use super::*;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::state::canister_state_bits::v1 as pb;

impl From<CyclesUseCase> for pb::CyclesUseCase {
    fn from(item: CyclesUseCase) -> Self {
        match item {
            CyclesUseCase::Memory => pb::CyclesUseCase::Memory,
            CyclesUseCase::ComputeAllocation => pb::CyclesUseCase::ComputeAllocation,
            CyclesUseCase::IngressInduction => pb::CyclesUseCase::IngressInduction,
            CyclesUseCase::Instructions => pb::CyclesUseCase::Instructions,
            CyclesUseCase::RequestAndResponseTransmission => {
                pb::CyclesUseCase::RequestAndResponseTransmission
            }
            CyclesUseCase::Uninstall => pb::CyclesUseCase::Uninstall,
            CyclesUseCase::CanisterCreation => pb::CyclesUseCase::CanisterCreation,
            CyclesUseCase::ECDSAOutcalls => pb::CyclesUseCase::EcdsaOutcalls,
            CyclesUseCase::HTTPOutcalls => pb::CyclesUseCase::HttpOutcalls,
            CyclesUseCase::DeletedCanisters => pb::CyclesUseCase::DeletedCanisters,
            CyclesUseCase::NonConsumed => pb::CyclesUseCase::NonConsumed,
            CyclesUseCase::BurnedCycles => pb::CyclesUseCase::BurnedCycles,
            CyclesUseCase::SchnorrOutcalls => pb::CyclesUseCase::SchnorrOutcalls,
            CyclesUseCase::VetKd => pb::CyclesUseCase::VetKd,
            CyclesUseCase::DroppedMessages => pb::CyclesUseCase::DroppedMessages,
        }
    }
}

impl TryFrom<pb::CyclesUseCase> for CyclesUseCase {
    type Error = ProxyDecodeError;
    fn try_from(item: pb::CyclesUseCase) -> Result<Self, Self::Error> {
        match item {
            pb::CyclesUseCase::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "CyclesUseCase",
                err: format!("Unexpected value of cycles use case: {item:?}"),
            }),
            pb::CyclesUseCase::Memory => Ok(Self::Memory),
            pb::CyclesUseCase::ComputeAllocation => Ok(Self::ComputeAllocation),
            pb::CyclesUseCase::IngressInduction => Ok(Self::IngressInduction),
            pb::CyclesUseCase::Instructions => Ok(Self::Instructions),
            pb::CyclesUseCase::RequestAndResponseTransmission => {
                Ok(Self::RequestAndResponseTransmission)
            }
            pb::CyclesUseCase::Uninstall => Ok(Self::Uninstall),
            pb::CyclesUseCase::CanisterCreation => Ok(Self::CanisterCreation),
            pb::CyclesUseCase::EcdsaOutcalls => Ok(Self::ECDSAOutcalls),
            pb::CyclesUseCase::HttpOutcalls => Ok(Self::HTTPOutcalls),
            pb::CyclesUseCase::DeletedCanisters => Ok(Self::DeletedCanisters),
            pb::CyclesUseCase::NonConsumed => Ok(Self::NonConsumed),
            pb::CyclesUseCase::BurnedCycles => Ok(Self::BurnedCycles),
            pb::CyclesUseCase::SchnorrOutcalls => Ok(Self::SchnorrOutcalls),
            pb::CyclesUseCase::VetKd => Ok(Self::VetKd),
            pb::CyclesUseCase::DroppedMessages => Ok(Self::DroppedMessages),
        }
    }
}

impl From<&CanisterStatus> for pb::canister_state_bits::CanisterStatus {
    fn from(item: &CanisterStatus) -> Self {
        match item {
            CanisterStatus::Running {
                call_context_manager,
            } => Self::Running(pb::CanisterStatusRunning {
                call_context_manager: Some(call_context_manager.into()),
            }),
            CanisterStatus::Stopped => Self::Stopped(pb::CanisterStatusStopped {}),
            CanisterStatus::Stopping {
                call_context_manager,
                stop_contexts,
            } => Self::Stopping(pb::CanisterStatusStopping {
                call_context_manager: Some(call_context_manager.into()),
                stop_contexts: stop_contexts.iter().map(|context| context.into()).collect(),
            }),
        }
    }
}

impl TryFrom<pb::canister_state_bits::CanisterStatus> for CanisterStatus {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::canister_state_bits::CanisterStatus) -> Result<Self, Self::Error> {
        let canister_status = match value {
            pb::canister_state_bits::CanisterStatus::Running(pb::CanisterStatusRunning {
                call_context_manager,
            }) => Self::Running {
                call_context_manager: try_from_option_field(
                    call_context_manager,
                    "CanisterStatus::Running::call_context_manager",
                )?,
            },
            pb::canister_state_bits::CanisterStatus::Stopped(pb::CanisterStatusStopped {}) => {
                Self::Stopped
            }
            pb::canister_state_bits::CanisterStatus::Stopping(pb::CanisterStatusStopping {
                call_context_manager,
                stop_contexts,
            }) => {
                let mut contexts = Vec::<StopCanisterContext>::with_capacity(stop_contexts.len());
                for context in stop_contexts.into_iter() {
                    contexts.push(context.try_into()?);
                }
                Self::Stopping {
                    call_context_manager: try_from_option_field(
                        call_context_manager,
                        "CanisterStatus::Stopping::call_context_manager",
                    )?,
                    stop_contexts: contexts,
                }
            }
        };
        Ok(canister_status)
    }
}

impl From<&ExecutionTask> for pb::ExecutionTask {
    fn from(item: &ExecutionTask) -> Self {
        match item {
            ExecutionTask::Heartbeat
            | ExecutionTask::GlobalTimer
            | ExecutionTask::OnLowWasmMemory
            | ExecutionTask::PausedExecution { .. }
            | ExecutionTask::PausedInstallCode(_) => {
                panic!("Attempt to serialize ephemeral task: {item:?}.");
            }
            ExecutionTask::AbortedExecution {
                input,
                prepaid_execution_cycles,
            } => {
                use pb::execution_task::{
                    CanisterTask as PbCanisterTask, aborted_execution::Input as PbInput,
                };
                let input = match input {
                    CanisterMessageOrTask::Message(CanisterMessage::Response(v)) => {
                        PbInput::Response(v.as_ref().into())
                    }
                    CanisterMessageOrTask::Message(CanisterMessage::Request(v)) => {
                        PbInput::Request(v.as_ref().into())
                    }
                    CanisterMessageOrTask::Message(CanisterMessage::Ingress(v)) => {
                        PbInput::Ingress(v.as_ref().into())
                    }
                    CanisterMessageOrTask::Task(task) => {
                        PbInput::Task(PbCanisterTask::from(task).into())
                    }
                };
                Self {
                    task: Some(pb::execution_task::Task::AbortedExecution(
                        pb::execution_task::AbortedExecution {
                            input: Some(input),
                            prepaid_execution_cycles: Some((*prepaid_execution_cycles).into()),
                        },
                    )),
                }
            }
            ExecutionTask::AbortedInstallCode {
                message,
                call_id,
                prepaid_execution_cycles,
            } => {
                use pb::execution_task::aborted_install_code::Message;
                let message = match message {
                    CanisterCall::Request(v) => Message::Request(v.as_ref().into()),
                    CanisterCall::Ingress(v) => Message::Ingress(v.as_ref().into()),
                };
                Self {
                    task: Some(pb::execution_task::Task::AbortedInstallCode(
                        pb::execution_task::AbortedInstallCode {
                            message: Some(message),
                            call_id: Some(call_id.get()),
                            prepaid_execution_cycles: Some((*prepaid_execution_cycles).into()),
                        },
                    )),
                }
            }
        }
    }
}

impl TryFrom<pb::ExecutionTask> for ExecutionTask {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::ExecutionTask) -> Result<Self, Self::Error> {
        let task = value
            .task
            .ok_or(ProxyDecodeError::MissingField("ExecutionTask::task"))?;
        let task = match task {
            pb::execution_task::Task::AbortedExecution(aborted) => {
                use pb::execution_task::{
                    CanisterTask as PbCanisterTask, aborted_execution::Input as PbInput,
                };
                let input = aborted
                    .input
                    .ok_or(ProxyDecodeError::MissingField("AbortedExecution::input"))?;
                let input = match input {
                    PbInput::Request(v) => CanisterMessageOrTask::Message(
                        CanisterMessage::Request(Arc::new(v.try_into()?)),
                    ),
                    PbInput::Response(v) => CanisterMessageOrTask::Message(
                        CanisterMessage::Response(Arc::new(v.try_into()?)),
                    ),
                    PbInput::Ingress(v) => CanisterMessageOrTask::Message(
                        CanisterMessage::Ingress(Arc::new(v.try_into()?)),
                    ),
                    PbInput::Task(val) => {
                        let task = CanisterTask::try_from(PbCanisterTask::try_from(val).map_err(
                            |_| ProxyDecodeError::ValueOutOfRange {
                                typ: "CanisterTask",
                                err: format!("Unexpected value of canister task: {val}"),
                            },
                        )?)?;
                        CanisterMessageOrTask::Task(task)
                    }
                };
                let prepaid_execution_cycles = aborted
                    .prepaid_execution_cycles
                    .map_or_else(Cycles::zero, |c| c.into());
                ExecutionTask::AbortedExecution {
                    input,
                    prepaid_execution_cycles,
                }
            }
            pb::execution_task::Task::AbortedInstallCode(aborted) => {
                use pb::execution_task::aborted_install_code::Message;
                let message = aborted.message.ok_or(ProxyDecodeError::MissingField(
                    "AbortedInstallCode::message",
                ))?;
                let message = match message {
                    Message::Request(v) => CanisterCall::Request(Arc::new(v.try_into()?)),
                    Message::Ingress(v) => CanisterCall::Ingress(Arc::new(v.try_into()?)),
                };
                let prepaid_execution_cycles = aborted
                    .prepaid_execution_cycles
                    .map_or_else(Cycles::zero, |c| c.into());
                let call_id = aborted.call_id.ok_or(ProxyDecodeError::MissingField(
                    "AbortedInstallCode::call_id",
                ))?;
                ExecutionTask::AbortedInstallCode {
                    message,
                    call_id: InstallCodeCallId::new(call_id),
                    prepaid_execution_cycles,
                }
            }
        };
        Ok(task)
    }
}

impl From<&CanisterHistory> for pb::CanisterHistory {
    fn from(item: &CanisterHistory) -> Self {
        Self {
            changes: item
                .changes
                .iter()
                .map(|e| (&(**e)).into())
                .collect::<Vec<pb::CanisterChange>>(),
            total_num_changes: item.total_num_changes,
        }
    }
}

impl TryFrom<pb::CanisterHistory> for CanisterHistory {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::CanisterHistory) -> Result<Self, Self::Error> {
        let changes = value
            .changes
            .into_iter()
            .map(|e| Ok(Arc::new(e.try_into()?)))
            .collect::<Result<VecDeque<_>, Self::Error>>()?;
        let canister_history_memory_usage = compute_total_canister_change_size(&changes);
        Ok(Self {
            changes: Arc::new(changes),
            total_num_changes: value.total_num_changes,
            canister_history_memory_usage,
        })
    }
}
