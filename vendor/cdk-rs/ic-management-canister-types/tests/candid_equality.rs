#![allow(unused)]
use candid::candid_method;
use ic_management_canister_types::*;

#[candid_method(update)]
fn create_canister(_: CreateCanisterArgs) -> CreateCanisterResult {
    unimplemented!()
}

#[candid_method(update)]
fn update_settings(_: UpdateSettingsArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn upload_chunk(_: UploadChunkArgs) -> UploadChunkResult {
    unimplemented!()
}

#[candid_method(update)]
fn clear_chunk_store(_: ClearChunkStoreArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn stored_chunks(_: StoredChunksArgs) -> StoredChunksResult {
    unimplemented!()
}

#[candid_method(update)]
fn install_code(_: InstallCodeArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn install_chunked_code(_: InstallChunkedCodeArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn uninstall_code(_: UninstallCodeArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn start_canister(_: StartCanisterArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn stop_canister(_: StopCanisterArgs) {
    unimplemented!()
}

#[candid_method(query)]
fn canister_status(_: CanisterStatusArgs) -> CanisterStatusResult {
    unimplemented!()
}

#[candid_method(update)]
fn canister_info(_: CanisterInfoArgs) -> CanisterInfoResult {
    unimplemented!()
}

#[candid_method(update)]
fn canister_metadata(_: CanisterMetadataArgs) -> CanisterMetadataResult {
    unimplemented!()
}

#[candid_method(update)]
fn subnet_info(_: SubnetInfoArgs) -> SubnetInfoResult {
    unimplemented!()
}

#[candid_method(update)]
fn delete_canister(_: DeleteCanisterArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn deposit_cycles(_: DepositCyclesArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn raw_rand() -> RawRandResult {
    unimplemented!()
}

#[candid_method(update)]
fn http_request(_: HttpRequestArgs) -> HttpRequestResult {
    unimplemented!()
}

#[candid_method(update)]
fn ecdsa_public_key(_: EcdsaPublicKeyArgs) -> EcdsaPublicKeyResult {
    unimplemented!()
}

#[candid_method(update)]
fn sign_with_ecdsa(_: SignWithEcdsaArgs) -> SignWithEcdsaResult {
    unimplemented!()
}

#[candid_method(update)]
fn schnorr_public_key(_: SchnorrPublicKeyArgs) -> SchnorrPublicKeyResult {
    unimplemented!()
}

#[candid_method(update)]
fn sign_with_schnorr(_: SignWithSchnorrArgs) -> SignWithSchnorrResult {
    unimplemented!()
}

#[candid_method(update)]
fn vetkd_public_key(_: VetKDPublicKeyArgs) -> VetKDPublicKeyResult {
    unimplemented!()
}

#[candid_method(update)]
fn vetkd_derive_key(_: VetKDDeriveKeyArgs) -> VetKDDeriveKeyResult {
    unimplemented!()
}

#[candid_method(update)]
fn node_metrics_history(_: NodeMetricsHistoryArgs) -> NodeMetricsHistoryResult {
    unimplemented!()
}

#[candid_method(update)]
fn provisional_create_canister_with_cycles(
    _: ProvisionalCreateCanisterWithCyclesArgs,
) -> ProvisionalCreateCanisterWithCyclesResult {
    unimplemented!()
}

#[candid_method(update)]
fn provisional_top_up_canister(_: ProvisionalTopUpCanisterArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn take_canister_snapshot(_: TakeCanisterSnapshotArgs) -> TakeCanisterSnapshotResult {
    unimplemented!()
}

#[candid_method(update)]
fn load_canister_snapshot(_: LoadCanisterSnapshotArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn list_canister_snapshots(_: ListCanisterSnapshotsArgs) -> ListCanisterSnapshotsResult {
    unimplemented!()
}

#[candid_method(update)]
fn delete_canister_snapshot(_: DeleteCanisterSnapshotArgs) {
    unimplemented!()
}

#[candid_method(update)]
fn read_canister_snapshot_metadata(
    _: ReadCanisterSnapshotMetadataArgs,
) -> ReadCanisterSnapshotMetadataResult {
    unimplemented!()
}

#[candid_method(update)]
fn read_canister_snapshot_data(_: ReadCanisterSnapshotDataArgs) -> ReadCanisterSnapshotDataResult {
    unimplemented!()
}

#[candid_method(update)]
fn upload_canister_snapshot_metadata(
    _: UploadCanisterSnapshotMetadataArgs,
) -> UploadCanisterSnapshotMetadataResult {
    unimplemented!()
}

#[candid_method(update)]
fn upload_canister_snapshot_data(_: UploadCanisterSnapshotDataArgs) {
    unimplemented!()
}

#[candid_method(query)]
fn fetch_canister_logs(_: FetchCanisterLogsArgs) -> FetchCanisterLogsResult {
    unimplemented!()
}

#[cfg(test)]
mod test {
    use candid_parser::utils::{CandidSource, service_equal};
    use ic_management_canister_types::*;

    #[test]
    fn candid_equality_test() {
        let declared_interface_str =
            std::fs::read_to_string("tests/ic.did").expect("Failed to read ic.did file");
        let filtered_interface_str = declared_interface_str
            .lines()
            // Bitcoin APIs are deprecated from the management canister, so we filter them out.
            .filter(|line| !line.trim_start().starts_with("bitcoin_"))
            .collect::<Vec<&str>>()
            .join("\n");
        let declared_interface = CandidSource::Text(&filtered_interface_str);

        candid::export_service!();
        let implemented_interface_str = __export_service();
        let implemented_interface = CandidSource::Text(&implemented_interface_str);

        let result = service_equal(declared_interface, implemented_interface);
        assert!(result.is_ok(), "{:?}", result.unwrap_err());
    }
}
