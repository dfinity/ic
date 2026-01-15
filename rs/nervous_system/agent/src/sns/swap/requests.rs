use ic_sns_swap::pb::v1::{
    ErrorRefundIcpRequest, ErrorRefundIcpResponse, FinalizeSwapRequest, FinalizeSwapResponse,
    GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse, GetBuyerStateRequest,
    GetBuyerStateResponse, GetDerivedStateRequest, GetDerivedStateResponse, GetInitRequest,
    GetInitResponse, GetLifecycleRequest, GetLifecycleResponse, GetOpenTicketRequest,
    GetOpenTicketResponse, ListSnsNeuronRecipesRequest, ListSnsNeuronRecipesResponse,
    NewSaleTicketRequest, NewSaleTicketResponse, RefreshBuyerTokensRequest,
    RefreshBuyerTokensResponse,
};

use crate::Request;

impl Request for GetDerivedStateRequest {
    fn method(&self) -> &'static str {
        "get_derived_state"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetDerivedStateResponse;
}

impl Request for GetInitRequest {
    fn method(&self) -> &'static str {
        "get_init"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetInitResponse;
}

impl Request for ListSnsNeuronRecipesRequest {
    fn method(&self) -> &'static str {
        "list_sns_neuron_recipes"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ListSnsNeuronRecipesResponse;
}

impl Request for NewSaleTicketRequest {
    fn method(&self) -> &'static str {
        "new_sale_ticket"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = NewSaleTicketResponse;
}

impl Request for RefreshBuyerTokensRequest {
    fn method(&self) -> &'static str {
        "refresh_buyer_tokens"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = RefreshBuyerTokensResponse;
}

impl Request for GetBuyerStateRequest {
    fn method(&self) -> &'static str {
        "get_buyer_state"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetBuyerStateResponse;
}

impl Request for GetOpenTicketRequest {
    fn method(&self) -> &'static str {
        "get_open_ticket"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetOpenTicketResponse;
}

impl Request for ErrorRefundIcpRequest {
    fn method(&self) -> &'static str {
        "error_refund_icp"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ErrorRefundIcpResponse;
}

impl Request for GetLifecycleRequest {
    fn method(&self) -> &'static str {
        "get_lifecycle"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetLifecycleResponse;
}

impl Request for FinalizeSwapRequest {
    fn method(&self) -> &'static str {
        "finalize_swap"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = FinalizeSwapResponse;
}

impl Request for GetAutoFinalizationStatusRequest {
    fn method(&self) -> &'static str {
        "get_auto_finalization_status"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetAutoFinalizationStatusResponse;
}
