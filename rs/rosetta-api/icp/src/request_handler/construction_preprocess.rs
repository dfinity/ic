use crate::convert::{self, to_model_account_identifier};
use crate::errors::ApiError;
use crate::models::{
    ConstructionMetadataRequestOptions, ConstructionPreprocessRequest,
    ConstructionPreprocessResponse,
};
use crate::request::Request;
use crate::request_handler::{verify_network_id, RosettaRequestHandler};
use crate::request_types::{
    AddHotKey, ChangeAutoStakeMaturity, Disburse, Follow, ListNeurons, MergeMaturity, NeuronInfo,
    RegisterVote, RemoveHotKey, SetDissolveTimestamp, Spawn, Stake, StakeMaturity, StartDissolve,
    StopDissolve,
};
use icp_ledger::Operation;
use std::collections::HashSet;

impl RosettaRequestHandler {
    /// Create a Request to Fetch Metadata.
    /// See https://www.rosetta-api.org/docs/ConstructionApi.html#constructionpreprocess
    pub fn construction_preprocess(
        &self,
        msg: ConstructionPreprocessRequest,
    ) -> Result<ConstructionPreprocessResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let transfers =
            convert::operations_to_requests(&msg.operations, true, self.ledger.token_symbol())?;
        let options = Some(ConstructionMetadataRequestOptions {
            request_types: transfers
                .iter()
                .map(|r| r.request_type())
                .collect::<Result<_, _>>()?,
        });

        let required_public_keys: Result<HashSet<icp_ledger::AccountIdentifier>, ApiError> =
            transfers.into_iter().map(required_public_key).collect();

        let required_public_keys: Vec<_> = required_public_keys?
            .into_iter()
            .map(|x| to_model_account_identifier(&x))
            .collect();

        Ok(ConstructionPreprocessResponse {
            required_public_keys: Some(required_public_keys),
            options: options.map(|op| op.try_into()).transpose()?,
        })
    }
}

/// Return the public key required to complete a request.
fn required_public_key(request: Request) -> Result<icp_ledger::AccountIdentifier, ApiError> {
    match request {
        Request::Transfer(Operation::Transfer { from, spender, .. }) => {
            if spender.is_some() {
                return Err(ApiError::invalid_request(
                    "TransferFrom operations are not supported through Rosetta.",
                ));
            }
            Ok(from)
        }
        Request::Transfer(Operation::Burn { .. }) => Err(ApiError::invalid_request(
            "Burn operations are not supported through rosetta",
        )),
        Request::Transfer(Operation::Mint { .. }) => Err(ApiError::invalid_request(
            "Mint operations are not supported through rosetta",
        )),
        Request::Transfer(Operation::Approve { .. }) => Err(ApiError::invalid_request(
            "Approve operations are not supported through rosetta",
        )),
        Request::Stake(Stake { account, .. })
        | Request::SetDissolveTimestamp(SetDissolveTimestamp { account, .. })
        | Request::ChangeAutoStakeMaturity(ChangeAutoStakeMaturity { account, .. })
        | Request::StartDissolve(StartDissolve { account, .. })
        | Request::StopDissolve(StopDissolve { account, .. })
        | Request::Disburse(Disburse { account, .. })
        | Request::AddHotKey(AddHotKey { account, .. })
        | Request::RemoveHotKey(RemoveHotKey { account, .. })
        | Request::Spawn(Spawn { account, .. })
        | Request::RegisterVote(RegisterVote { account, .. })
        | Request::MergeMaturity(MergeMaturity { account, .. })
        | Request::StakeMaturity(StakeMaturity { account, .. })
        | Request::NeuronInfo(NeuronInfo { account, .. })
        | Request::ListNeurons(ListNeurons { account, .. })
        | Request::Follow(Follow { account, .. }) => Ok(account),
    }
}
