use crate::pb::v1::GovernanceError;
use ic_base_types::CanisterId;

/// A trait for proposal types that simply calls a canister method with a payload.
pub(crate) trait CallCanister {
    /// If a proposal (type) does not care about the reply (e.g. it carries no
    /// information anyway), just set this to (). See the implementation of
    /// CallCanisterReply for () below. In general though, do not throw away
    /// perfectly good data.
    type Reply: CallCanisterReply;

    /// Returns the target canister ID and method to call for proposal execution.
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError>;
    /// Returns the payload to send to the target canister.
    fn payload(&self) -> Result<Vec<u8>, GovernanceError>;
}

// TODO: impl CallCanister for ExecuteNnsFunction

/// perform_call_canister uses this to decode the reply.
pub(crate) trait CallCanisterReply: Sized {
    fn try_decode(encoded_reply: &[u8]) -> Result<Option<Self>, GovernanceError>;
}

// This implementation for () throws data away. This is, of course, evil.
// This nevertheless exists because we had code that threw data away before
// this trait was introduced. Hopefully, no more uses of this are added...
impl CallCanisterReply for () {
    fn try_decode(_encoded_reply: &[u8]) -> Result<Option<Self>, GovernanceError> {
        Ok(None)
    }
}
