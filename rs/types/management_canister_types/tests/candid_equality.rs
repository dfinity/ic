#![allow(unused)]
use candid::candid_method;
use ic_management_canister_types_private::*;

// The following types have different names in `ic-management-canister-types` and `ic-management-canister-types-private`:
type CreateCanisterResult = CanisterIdRecord;
type UploadChunkResult = UploadChunkReply;
type StoredChunksResult = StoredChunksReply;
//type InstallCodeArgs = InstallCodeArgsV2; // inlined due to clash with `ic_management_canister_types_private::InstallCodeArgs`
type StartCanisterArgs = CanisterIdRecord;
type StopCanisterArgs = CanisterIdRecord;
type CanisterStatusArgs = CanisterIdRecord;
type CanisterStatusResult = CanisterStatusResultV2;
type CanisterInfoArgs = CanisterInfoRequest;
type CanisterInfoResult = CanisterInfoResponse;
type CanisterMetadataArgs = CanisterMetadataRequest;
type CanisterMetadataResult = CanisterMetadataResponse;
type SubnetInfoResult = SubnetInfoResponse;
type DeleteCanisterArgs = CanisterIdRecord;
type DepositCyclesArgs = CanisterIdRecord;
type RawRandResult = Vec<u8>;
type HttpRequestArgs = CanisterHttpRequestArgs;
type HttpRequestResult = CanisterHttpResponsePayload;
type EcdsaPublicKeyArgs = ECDSAPublicKeyArgs;
type EcdsaPublicKeyResult = ECDSAPublicKeyResponse;
type SignWithEcdsaArgs = SignWithECDSAArgs;
type SignWithEcdsaResult = SignWithECDSAReply;
type SchnorrPublicKeyResult = SchnorrPublicKeyResponse;
type SignWithSchnorrResult = SignWithSchnorrReply;
type NodeMetricsHistoryResult = Vec<NodeMetricsHistoryResponse>;
type ProvisionalCreateCanisterWithCyclesResult = CanisterIdRecord;
type TakeCanisterSnapshotResult = CanisterSnapshotResponse;
type ListCanisterSnapshotsArgs = CanisterIdRecord;
type ListCanisterSnapshotsResult = Vec<CanisterSnapshotResponse>;
type FetchCanisterLogsArgs = FetchCanisterLogsRequest;
type FetchCanisterLogsResult = FetchCanisterLogsResponse;

#[candid_method(update)]
fn create_canister(_: CreateCanisterArgs) -> CreateCanisterResult {
    unreachable!()
}

#[candid_method(update)]
fn update_settings(_: UpdateSettingsArgs) {
    unreachable!()
}

#[candid_method(update)]
fn upload_chunk(_: UploadChunkArgs) -> UploadChunkResult {
    unreachable!()
}

#[candid_method(update)]
fn clear_chunk_store(_: ClearChunkStoreArgs) {
    unreachable!()
}

#[candid_method(update)]
fn stored_chunks(_: StoredChunksArgs) -> StoredChunksResult {
    unreachable!()
}

#[candid_method(update)]
fn install_code(_: InstallCodeArgsV2) {
    unreachable!()
}

#[candid_method(update)]
fn install_chunked_code(_: InstallChunkedCodeArgs) {
    unreachable!()
}

#[candid_method(update)]
fn uninstall_code(_: UninstallCodeArgs) {
    unreachable!()
}

#[candid_method(update)]
fn start_canister(_: StartCanisterArgs) {
    unreachable!()
}

#[candid_method(update)]
fn stop_canister(_: StopCanisterArgs) {
    unreachable!()
}

#[candid_method(update)]
fn canister_status(_: CanisterStatusArgs) -> CanisterStatusResult {
    unreachable!()
}

#[candid_method(update)]
fn canister_info(_: CanisterInfoArgs) -> CanisterInfoResult {
    unreachable!()
}

#[candid_method(update)]
fn canister_metadata(_: CanisterMetadataArgs) -> CanisterMetadataResult {
    unreachable!()
}

#[candid_method(update)]
fn subnet_info(_: SubnetInfoArgs) -> SubnetInfoResult {
    unreachable!()
}

#[candid_method(update)]
fn delete_canister(_: DeleteCanisterArgs) {
    unreachable!()
}

#[candid_method(update)]
fn deposit_cycles(_: DepositCyclesArgs) {
    unreachable!()
}

#[candid_method(update)]
fn raw_rand() -> RawRandResult {
    unreachable!()
}

#[candid_method(update)]
fn http_request(_: HttpRequestArgs) -> HttpRequestResult {
    unreachable!()
}

#[candid_method(update)]
fn ecdsa_public_key(_: EcdsaPublicKeyArgs) -> EcdsaPublicKeyResult {
    unreachable!()
}

#[candid_method(update)]
fn sign_with_ecdsa(_: SignWithEcdsaArgs) -> SignWithEcdsaResult {
    unreachable!()
}

#[candid_method(update)]
fn schnorr_public_key(_: SchnorrPublicKeyArgs) -> SchnorrPublicKeyResult {
    unreachable!()
}

#[candid_method(update)]
fn sign_with_schnorr(_: SignWithSchnorrArgs) -> SignWithSchnorrResult {
    unreachable!()
}

#[candid_method(update)]
fn node_metrics_history(_: NodeMetricsHistoryArgs) -> NodeMetricsHistoryResult {
    unreachable!()
}

#[candid_method(update)]
fn provisional_create_canister_with_cycles(
    _: ProvisionalCreateCanisterWithCyclesArgs,
) -> ProvisionalCreateCanisterWithCyclesResult {
    unreachable!()
}

#[candid_method(update)]
fn provisional_top_up_canister(_: ProvisionalTopUpCanisterArgs) {
    unreachable!()
}

#[candid_method(update)]
fn take_canister_snapshot(_: TakeCanisterSnapshotArgs) -> TakeCanisterSnapshotResult {
    unreachable!()
}

#[candid_method(update)]
fn load_canister_snapshot(_: LoadCanisterSnapshotArgs) {
    unreachable!()
}

#[candid_method(update)]
fn list_canister_snapshots(_: ListCanisterSnapshotsArgs) -> ListCanisterSnapshotsResult {
    unreachable!()
}

#[candid_method(update)]
fn delete_canister_snapshot(_: DeleteCanisterSnapshotArgs) {
    unreachable!()
}

#[candid_method(query)]
fn fetch_canister_logs(_: FetchCanisterLogsArgs) -> FetchCanisterLogsResult {
    unreachable!()
}

#[candid_method(update)]
fn read_canister_snapshot_metadata(
    _: ReadCanisterSnapshotMetadataArgs,
) -> ReadCanisterSnapshotMetadataResponse {
    unreachable!()
}

#[candid_method(update)]
fn read_canister_snapshot_data(
    _: ReadCanisterSnapshotDataArgs,
) -> ReadCanisterSnapshotDataResponse {
    unreachable!()
}

#[candid_method(update)]
fn upload_canister_snapshot_metadata(
    _: UploadCanisterSnapshotMetadataArgs,
) -> UploadCanisterSnapshotMetadataResponse {
    unreachable!()
}

#[candid_method(update)]
fn upload_canister_snapshot_data(_: UploadCanisterSnapshotDataArgs) {
    unreachable!()
}

#[candid_method(update)]
fn rename_canister(_: RenameCanisterArgs) {
    unreachable!()
}

#[cfg(test)]
mod test {
    use crate::*;
    use candid_parser::utils::{CandidSource, service_equal};
    use ic_management_canister_types_private::*;

    #[test]
    fn candid_equality_test() {
        let ic_did_path =
            std::env::var("IC_DID").expect("Failed to read IC_DID environment variable");
        let declared_interface_str =
            std::fs::read_to_string(ic_did_path).expect("Failed to read ic.did file");
        let declared_interface = CandidSource::Text(&declared_interface_str);

        candid::export_service!();
        let implemented_interface_str = __export_service();
        let implemented_interface = CandidSource::Text(&implemented_interface_str);

        let result = service_equal(declared_interface, implemented_interface);
        assert!(result.is_ok(), "{:?}", result.unwrap_err());
    }
}
