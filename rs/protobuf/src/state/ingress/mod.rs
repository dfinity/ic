#[allow(clippy::all)]
pub mod v1 {
    use crate::proxy::ProxyDecodeError;
    use ic_error_types::ErrorCode as ErrorCodePublic;

    include!("../../gen/state/state.ingress.v1.rs");

    impl From<ErrorCodePublic> for ErrorCode {
        fn from(item: ErrorCodePublic) -> Self {
            match item {
                ErrorCodePublic::SubnetOversubscribed => ErrorCode::SubnetOversubscribed,
                ErrorCodePublic::MaxNumberOfCanistersReached => {
                    ErrorCode::MaxNumberOfCanistersReached
                }
                ErrorCodePublic::CanisterQueueFull => ErrorCode::CanisterQueueFull,
                ErrorCodePublic::IngressMessageTimeout => ErrorCode::IngressMessageTimeout,
                ErrorCodePublic::CanisterQueueNotEmpty => ErrorCode::CanisterQueueNotEmpty,
                ErrorCodePublic::IngressHistoryFull => ErrorCode::IngressHistoryFull,
                ErrorCodePublic::CanisterIdAlreadyExists => ErrorCode::CanisterIdAlreadyExists,
                ErrorCodePublic::StopCanisterRequestTimeout => {
                    ErrorCode::StopCanisterRequestTimeout
                }
                ErrorCodePublic::CanisterOutOfCycles => ErrorCode::CanisterOutOfCycles,
                ErrorCodePublic::CertifiedStateUnavailable => ErrorCode::CertifiedStateUnavailable,
                ErrorCodePublic::CanisterInstallCodeRateLimited => {
                    ErrorCode::CanisterInstallCodeRateLimited
                }
                ErrorCodePublic::CanisterHeapDeltaRateLimited => {
                    ErrorCode::CanisterHeapDeltaRateLimited
                }
                ErrorCodePublic::CanisterNotFound => ErrorCode::CanisterNotFound,
                ErrorCodePublic::CanisterSnapshotNotFound => ErrorCode::CanisterSnapshotNotFound,
                ErrorCodePublic::CanisterSnapshotImmutable => ErrorCode::CanisterSnapshotImmutable,
                ErrorCodePublic::InsufficientMemoryAllocation => {
                    ErrorCode::InsufficientMemoryAllocation
                }
                ErrorCodePublic::InsufficientCyclesForCreateCanister => {
                    ErrorCode::InsufficientCyclesForCreateCanister
                }
                ErrorCodePublic::SubnetNotFound => ErrorCode::SubnetNotFound,
                ErrorCodePublic::CanisterNotHostedBySubnet => ErrorCode::CanisterNotHostedBySubnet,
                ErrorCodePublic::CanisterRejectedMessage => ErrorCode::CanisterRejectedMessage,
                ErrorCodePublic::UnknownManagementMessage => ErrorCode::UnknownManagementMessage,
                ErrorCodePublic::InvalidManagementPayload => ErrorCode::InvalidManagementPayload,
                ErrorCodePublic::CanisterTrapped => ErrorCode::CanisterTrapped,
                ErrorCodePublic::CanisterCalledTrap => ErrorCode::CanisterCalledTrap,
                ErrorCodePublic::CanisterContractViolation => ErrorCode::CanisterContractViolation,
                ErrorCodePublic::CanisterInvalidWasm => ErrorCode::CanisterInvalidWasm,
                ErrorCodePublic::CanisterDidNotReply => ErrorCode::CanisterDidNotReply,
                ErrorCodePublic::CanisterOutOfMemory => ErrorCode::CanisterOutOfMemory,
                ErrorCodePublic::CanisterStopped => ErrorCode::CanisterStopped,
                ErrorCodePublic::CanisterStopping => ErrorCode::CanisterStopping,
                ErrorCodePublic::CanisterNotStopped => ErrorCode::CanisterNotStopped,
                ErrorCodePublic::CanisterStoppingCancelled => ErrorCode::CanisterStoppingCancelled,
                ErrorCodePublic::CanisterInvalidController => ErrorCode::CanisterInvalidController,
                ErrorCodePublic::CanisterFunctionNotFound => ErrorCode::CanisterFunctionNotFound,
                ErrorCodePublic::CanisterNonEmpty => ErrorCode::CanisterNonEmpty,
                ErrorCodePublic::QueryCallGraphLoopDetected => {
                    ErrorCode::QueryCallGraphLoopDetected
                }
                ErrorCodePublic::InsufficientCyclesInCall => ErrorCode::InsufficientCyclesInCall,
                ErrorCodePublic::CanisterWasmEngineError => ErrorCode::CanisterWasmEngineError,
                ErrorCodePublic::CanisterInstructionLimitExceeded => {
                    ErrorCode::CanisterInstructionLimitExceeded
                }
                ErrorCodePublic::CanisterMemoryAccessLimitExceeded => {
                    ErrorCode::CanisterMemoryAccessLimitExceeded
                }
                ErrorCodePublic::QueryCallGraphTooDeep => ErrorCode::QueryCallGraphTooDeep,
                ErrorCodePublic::QueryCallGraphTotalInstructionLimitExceeded => {
                    ErrorCode::QueryCallGraphTotalInstructionLimitExceeded
                }
                ErrorCodePublic::CompositeQueryCalledInReplicatedMode => {
                    ErrorCode::CompositeQueryCalledInReplicatedMode
                }
                ErrorCodePublic::QueryTimeLimitExceeded => ErrorCode::QueryTimeLimitExceeded,
                ErrorCodePublic::QueryCallGraphInternal => ErrorCode::QueryCallGraphInternal,
                ErrorCodePublic::InsufficientCyclesInComputeAllocation => {
                    ErrorCode::InsufficientCyclesInComputeAllocation
                }
                ErrorCodePublic::InsufficientCyclesInMemoryAllocation => {
                    ErrorCode::InsufficientCyclesInMemoryAllocation
                }
                ErrorCodePublic::InsufficientCyclesInMemoryGrow => {
                    ErrorCode::InsufficientCyclesInMemoryGrow
                }
                ErrorCodePublic::ReservedCyclesLimitExceededInMemoryAllocation => {
                    ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation
                }
                ErrorCodePublic::ReservedCyclesLimitExceededInMemoryGrow => {
                    ErrorCode::ReservedCyclesLimitExceededInMemoryGrow
                }
                ErrorCodePublic::InsufficientCyclesInMessageMemoryGrow => {
                    ErrorCode::InsufficientCyclesInMessageMemoryGrow
                }
                ErrorCodePublic::CanisterMethodNotFound => ErrorCode::CanisterMethodNotFound,
                ErrorCodePublic::CanisterWasmModuleNotFound => {
                    ErrorCode::CanisterWasmModuleNotFound
                }
                ErrorCodePublic::CanisterAlreadyInstalled => ErrorCode::CanisterAlreadyInstalled,
                ErrorCodePublic::CanisterWasmMemoryLimitExceeded => {
                    ErrorCode::CanisterWasmMemoryLimitExceeded
                }
                ErrorCodePublic::ReservedCyclesLimitIsTooLow => {
                    ErrorCode::ReservedCyclesLimitIsTooLow
                }
                ErrorCodePublic::DeadlineExpired => ErrorCode::DeadlineExpired,
                ErrorCodePublic::ResponseDropped => ErrorCode::ResponseDropped,
            }
        }
    }

    impl TryFrom<ErrorCode> for ErrorCodePublic {
        type Error = ProxyDecodeError;
        fn try_from(code: ErrorCode) -> Result<ErrorCodePublic, Self::Error> {
            match code {
                ErrorCode::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                    typ: "ErrorCodePublic",
                    err: format!("Unexpected value of error code: {:?}", code),
                }),
                ErrorCode::SubnetOversubscribed => Ok(ErrorCodePublic::SubnetOversubscribed),
                ErrorCode::MaxNumberOfCanistersReached => {
                    Ok(ErrorCodePublic::MaxNumberOfCanistersReached)
                }
                ErrorCode::CanisterQueueFull => Ok(ErrorCodePublic::CanisterQueueFull),
                ErrorCode::IngressMessageTimeout => Ok(ErrorCodePublic::IngressMessageTimeout),
                ErrorCode::CanisterQueueNotEmpty => Ok(ErrorCodePublic::CanisterQueueNotEmpty),
                ErrorCode::IngressHistoryFull => Ok(ErrorCodePublic::IngressHistoryFull),
                ErrorCode::CanisterIdAlreadyExists => Ok(ErrorCodePublic::CanisterIdAlreadyExists),
                ErrorCode::StopCanisterRequestTimeout => {
                    Ok(ErrorCodePublic::StopCanisterRequestTimeout)
                }
                ErrorCode::CanisterOutOfCycles => Ok(ErrorCodePublic::CanisterOutOfCycles),
                ErrorCode::CertifiedStateUnavailable => {
                    Ok(ErrorCodePublic::CertifiedStateUnavailable)
                }
                ErrorCode::CanisterInstallCodeRateLimited => {
                    Ok(ErrorCodePublic::CanisterInstallCodeRateLimited)
                }
                ErrorCode::CanisterHeapDeltaRateLimited => {
                    Ok(ErrorCodePublic::CanisterHeapDeltaRateLimited)
                }
                ErrorCode::CanisterNotFound => Ok(ErrorCodePublic::CanisterNotFound),
                ErrorCode::CanisterSnapshotNotFound => {
                    Ok(ErrorCodePublic::CanisterSnapshotNotFound)
                }
                ErrorCode::CanisterSnapshotImmutable => {
                    Ok(ErrorCodePublic::CanisterSnapshotImmutable)
                }
                ErrorCode::InsufficientMemoryAllocation => {
                    Ok(ErrorCodePublic::InsufficientMemoryAllocation)
                }
                ErrorCode::InsufficientCyclesForCreateCanister => {
                    Ok(ErrorCodePublic::InsufficientCyclesForCreateCanister)
                }
                ErrorCode::SubnetNotFound => Ok(ErrorCodePublic::SubnetNotFound),
                ErrorCode::CanisterNotHostedBySubnet => {
                    Ok(ErrorCodePublic::CanisterNotHostedBySubnet)
                }
                ErrorCode::CanisterRejectedMessage => Ok(ErrorCodePublic::CanisterRejectedMessage),
                ErrorCode::UnknownManagementMessage => {
                    Ok(ErrorCodePublic::UnknownManagementMessage)
                }
                ErrorCode::InvalidManagementPayload => {
                    Ok(ErrorCodePublic::InvalidManagementPayload)
                }
                ErrorCode::CanisterTrapped => Ok(ErrorCodePublic::CanisterTrapped),
                ErrorCode::CanisterCalledTrap => Ok(ErrorCodePublic::CanisterCalledTrap),
                ErrorCode::CanisterContractViolation => {
                    Ok(ErrorCodePublic::CanisterContractViolation)
                }
                ErrorCode::CanisterInvalidWasm => Ok(ErrorCodePublic::CanisterInvalidWasm),
                ErrorCode::CanisterDidNotReply => Ok(ErrorCodePublic::CanisterDidNotReply),
                ErrorCode::CanisterOutOfMemory => Ok(ErrorCodePublic::CanisterOutOfMemory),
                ErrorCode::CanisterStopped => Ok(ErrorCodePublic::CanisterStopped),
                ErrorCode::CanisterStopping => Ok(ErrorCodePublic::CanisterStopping),
                ErrorCode::CanisterNotStopped => Ok(ErrorCodePublic::CanisterNotStopped),
                ErrorCode::CanisterStoppingCancelled => {
                    Ok(ErrorCodePublic::CanisterStoppingCancelled)
                }
                ErrorCode::CanisterInvalidController => {
                    Ok(ErrorCodePublic::CanisterInvalidController)
                }
                ErrorCode::CanisterFunctionNotFound => {
                    Ok(ErrorCodePublic::CanisterFunctionNotFound)
                }
                ErrorCode::CanisterNonEmpty => Ok(ErrorCodePublic::CanisterNonEmpty),
                ErrorCode::QueryCallGraphLoopDetected => {
                    Ok(ErrorCodePublic::QueryCallGraphLoopDetected)
                }
                ErrorCode::InsufficientCyclesInCall => {
                    Ok(ErrorCodePublic::InsufficientCyclesInCall)
                }
                ErrorCode::CanisterWasmEngineError => Ok(ErrorCodePublic::CanisterWasmEngineError),
                ErrorCode::CanisterInstructionLimitExceeded => {
                    Ok(ErrorCodePublic::CanisterInstructionLimitExceeded)
                }
                ErrorCode::CanisterMemoryAccessLimitExceeded => {
                    Ok(ErrorCodePublic::CanisterMemoryAccessLimitExceeded)
                }
                ErrorCode::QueryCallGraphTooDeep => Ok(ErrorCodePublic::QueryCallGraphTooDeep),
                ErrorCode::QueryCallGraphTotalInstructionLimitExceeded => {
                    Ok(ErrorCodePublic::QueryCallGraphTotalInstructionLimitExceeded)
                }
                ErrorCode::CompositeQueryCalledInReplicatedMode => {
                    Ok(ErrorCodePublic::CompositeQueryCalledInReplicatedMode)
                }
                ErrorCode::QueryTimeLimitExceeded => Ok(ErrorCodePublic::QueryTimeLimitExceeded),
                ErrorCode::QueryCallGraphInternal => Ok(ErrorCodePublic::QueryCallGraphInternal),
                ErrorCode::InsufficientCyclesInComputeAllocation => {
                    Ok(ErrorCodePublic::InsufficientCyclesInComputeAllocation)
                }
                ErrorCode::InsufficientCyclesInMemoryAllocation => {
                    Ok(ErrorCodePublic::InsufficientCyclesInMemoryAllocation)
                }
                ErrorCode::InsufficientCyclesInMemoryGrow => {
                    Ok(ErrorCodePublic::InsufficientCyclesInMemoryGrow)
                }
                ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation => {
                    Ok(ErrorCodePublic::ReservedCyclesLimitExceededInMemoryAllocation)
                }
                ErrorCode::ReservedCyclesLimitExceededInMemoryGrow => {
                    Ok(ErrorCodePublic::ReservedCyclesLimitExceededInMemoryGrow)
                }
                ErrorCode::InsufficientCyclesInMessageMemoryGrow => {
                    Ok(ErrorCodePublic::InsufficientCyclesInMessageMemoryGrow)
                }
                ErrorCode::CanisterMethodNotFound => Ok(ErrorCodePublic::CanisterMethodNotFound),
                ErrorCode::CanisterWasmModuleNotFound => {
                    Ok(ErrorCodePublic::CanisterWasmModuleNotFound)
                }
                ErrorCode::CanisterAlreadyInstalled => {
                    Ok(ErrorCodePublic::CanisterAlreadyInstalled)
                }
                ErrorCode::CanisterWasmMemoryLimitExceeded => {
                    Ok(ErrorCodePublic::CanisterWasmMemoryLimitExceeded)
                }
                ErrorCode::ReservedCyclesLimitIsTooLow => {
                    Ok(ErrorCodePublic::ReservedCyclesLimitIsTooLow)
                }
                ErrorCode::DeadlineExpired => Ok(ErrorCodePublic::DeadlineExpired),
                ErrorCode::ResponseDropped => Ok(ErrorCodePublic::ResponseDropped),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::ErrorCode as ErrorCodeProto;
        use ic_error_types::ErrorCode;
        use strum::IntoEnumIterator;

        #[test]
        fn error_code_round_trip() {
            for initial in ErrorCode::iter() {
                let encoded = ErrorCodeProto::from(initial);
                let round_trip = ErrorCode::try_from(encoded).unwrap();

                assert_eq!(initial, round_trip);
            }
        }
    }
}
