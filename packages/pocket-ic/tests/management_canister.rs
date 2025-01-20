use ic_cdk::{query, update};
use pocket_ic::management_canister::*;

#[update]
fn create_canister(_: CreateCanisterArgs) -> CanisterIdRecord {
    unreachable!()
}

#[update]
fn update_settings(_: UpdateSettingsArgs) {
    unreachable!()
}

#[update]
fn upload_chunk(_: UploadChunkArgs) -> UploadChunkResult {
    unreachable!()
}

#[update]
fn clear_chunk_store(_: CanisterIdRecord) {
    unreachable!()
}

#[update]
fn stored_chunks(_: CanisterIdRecord) -> StoredChunksResult {
    unreachable!()
}

#[update]
fn install_code(_: InstallCodeArgs) {
    unreachable!()
}

#[update]
fn install_chunked_code(_: InstallChunkedCodeArgs) {
    unreachable!()
}

#[update]
fn uninstall_code(_: UninstallCodeArgs) {
    unreachable!()
}

#[update]
fn start_canister(_: CanisterIdRecord) {
    unreachable!()
}

#[update]
fn stop_canister(_: CanisterIdRecord) {
    unreachable!()
}

#[update]
fn canister_status(_: CanisterIdRecord) -> CanisterStatusResult {
    unreachable!()
}

#[update]
fn canister_info(_: CanisterInfoArgs) -> CanisterInfoResult {
    unreachable!()
}

#[update]
fn subnet_info(_: SubnetInfoArgs) -> SubnetInfoResult {
    unreachable!()
}

#[update]
fn delete_canister(_: CanisterIdRecord) {
    unreachable!()
}

#[update]
fn deposit_cycles(_: CanisterIdRecord) {
    unreachable!()
}

#[update]
fn raw_rand() -> RawRandResult {
    unreachable!()
}

#[update]
fn http_request(_: HttpRequestArgs) -> HttpRequestResult {
    unreachable!()
}

#[update]
fn ecdsa_public_key(_: EcdsaPublicKeyArgs) -> EcdsaPublicKeyResult {
    unreachable!()
}

#[update]
fn sign_with_ecdsa(_: SignWithEcdsaArgs) -> SignWithEcdsaResult {
    unreachable!()
}

#[update]
fn schnorr_public_key(_: SchnorrPublicKeyArgs) -> SchnorrPublicKeyResult {
    unreachable!()
}

#[update]
fn sign_with_schnorr(_: SignWithSchnorrArgs) -> SignWithSchnorrResult {
    unreachable!()
}

#[update]
fn bitcoin_get_balance(_: BitcoinGetBalanceArgs) -> BitcoinGetBalanceResult {
    unreachable!()
}

#[update]
fn bitcoin_get_utxos(_: BitcoinGetUtxosArgs) -> BitcoinGetUtxosResult {
    unreachable!()
}

#[update]
fn bitcoin_send_transaction(_: BitcoinSendTransactionArgs) {
    unreachable!()
}

#[update]
fn bitcoin_get_current_fee_percentiles(
    _: BitcoinGetCurrentFeePercentilesArgs,
) -> BitcoinGetCurrentFeePercentilesResult {
    unreachable!()
}

#[update]
fn bitcoin_get_block_headers(_: BitcoinGetBlockHeadersArgs) -> BitcoinGetBlockHeadersResult {
    unreachable!()
}

#[update]
fn node_metrics_history(_: NodeMetricsHistoryArgs) -> NodeMetricsHistoryResult {
    unreachable!()
}

#[update]
fn provisional_create_canister_with_cycles(
    _: ProvisionalCreateCanisterWithCyclesArgs,
) -> CanisterIdRecord {
    unreachable!()
}

#[update]
fn provisional_top_up_canister(_: ProvisionalTopUpCanisterArgs) {
    unreachable!()
}

#[update]
fn take_canister_snapshot(_: TakeCanisterSnapshotArgs) -> TakeCanisterSnapshotResult {
    unreachable!()
}

#[update]
fn load_canister_snapshot(_: LoadCanisterSnapshotArgs) {
    unreachable!()
}

#[update]
fn list_canister_snapshots(_: CanisterIdRecord) -> ListCanisterSnapshotsResult {
    unreachable!()
}

#[update]
fn delete_canister_snapshot(_: DeleteCanisterSnapshotArgs) {
    unreachable!()
}

#[query]
fn fetch_canister_logs(_: CanisterIdRecord) -> FetchCanisterLogsResult {
    unreachable!()
}

#[cfg(test)]
mod test {
    use candid_parser::utils::{service_equal, CandidSource};
    use pocket_ic::management_canister::*;

    #[test]
    fn candid_equality_test() {
        let declared_interface_str =
            std::fs::read_to_string(std::env::var_os("IC_DID").unwrap()).unwrap();
        let declared_interface = CandidSource::Text(&declared_interface_str);

        candid::export_service!();
        let implemented_interface_str = __export_service();
        let implemented_interface = CandidSource::Text(&implemented_interface_str);

        let result = service_equal(declared_interface, implemented_interface);
        assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
    }
}
