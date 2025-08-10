use super::Request;
use candid::Encode;
use ic_registry_canister_api::mutate_test_high_capacity_records::Request as MutateTestHighCapacityRecordsRequest;

impl Request for MutateTestHighCapacityRecordsRequest {
    fn method(&self) -> &'static str {
        "mutate_test_high_capacity_records"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        Encode!(self)
    }

    type Response = u64;
}
