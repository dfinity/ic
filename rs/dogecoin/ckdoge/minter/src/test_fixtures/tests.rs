mod arbitrary {
    use crate::test_fixtures::arbitrary::ckbtc;
    use ic_ckbtc_minter::state::eventlog::{EventType as CkBtcMinterEventType, EventType};
    use proptest::strategy::Strategy;

    #[test]
    fn should_have_one_strategy_per_event() {
        let dummy_event = CkBtcMinterEventType::RemovedRetrieveBtcRequest { block_index: 0 };

        let _strategy = match dummy_event {
            EventType::Init(_) => ckbtc::init().boxed(),
            EventType::Upgrade(_) => ckbtc::upgrade().boxed(),
            EventType::ReceivedUtxos { .. } => ckbtc::received_utxos().boxed(),
            EventType::AcceptedRetrieveBtcRequest(_) => {
                ckbtc::accepted_retrieve_btc_request().boxed()
            }
            EventType::RemovedRetrieveBtcRequest { .. } => {
                ckbtc::removed_retrieve_btc_request().boxed()
            }
            EventType::SentBtcTransaction { .. } => ckbtc::send_btc_transaction().boxed(),
            EventType::ReplacedBtcTransaction { .. } => ckbtc::replaced_btc_transaction().boxed(),
            EventType::ConfirmedBtcTransaction { .. } => ckbtc::confirmed_btc_transaction().boxed(),
            #[allow(deprecated)]
            EventType::CheckedUtxo { .. } => ckbtc::checked_utxo().boxed(),
            EventType::CheckedUtxoV2 { .. } => ckbtc::checked_utxo_v2().boxed(),
            #[allow(deprecated)]
            EventType::IgnoredUtxo { .. } => ckbtc::ignored_utxo().boxed(),
            EventType::SuspendedUtxo { .. } => ckbtc::suspended_utxo().boxed(),
            EventType::DistributedKytFee { .. } => ckbtc::distributed_kyt_fee().boxed(),
            #[allow(deprecated)]
            EventType::RetrieveBtcKytFailed { .. } => ckbtc::retrieve_btc_kyt_failed().boxed(),
            EventType::ScheduleDepositReimbursement { .. } => {
                ckbtc::schedule_deposit_reimbursement().boxed()
            }
            EventType::ReimbursedFailedDeposit { .. } => ckbtc::reimbursed_failed_deposit().boxed(),
            EventType::CheckedUtxoMintUnknown { .. } => ckbtc::checked_utxo_mint_unknown().boxed(),
            EventType::ScheduleWithdrawalReimbursement { .. } => {
                ckbtc::schedule_withdrawal_reimbursement().boxed()
            }
            EventType::QuarantinedWithdrawalReimbursement { .. } => {
                ckbtc::quarantined_withdrawal_reimbursement().boxed()
            }
            EventType::ReimbursedWithdrawal { .. } => ckbtc::reimbursed_withdrawal().boxed(),
            EventType::CreatedConsolidateUtxosRequest(_) => {
                ckbtc::create_consolidate_utxos_request().boxed()
            }
        };
    }
}
