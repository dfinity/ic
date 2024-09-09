use candid::{Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger::{InitArgs as Icrc1InitArgs, LedgerArgument};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};
use ic_nns_test_utils::state_test_helpers::icrc1_transfer;
use ic_sns_swap::{
    pb::v1::{
        new_sale_ticket_response, BuyerState, GetLifecycleResponse, Init, Lifecycle,
        NeuronBasketConstructionParameters, NewSaleTicketResponse, Params,
        RefreshBuyerTokensResponse, Ticket,
    },
    swap::principal_to_subaccount,
};
use ic_sns_test_utils::state_test_helpers::{
    get_buyer_state, get_buyers_total, get_lifecycle, get_open_ticket, get_sns_sale_parameters,
    new_sale_ticket, notify_payment_failure, refresh_buyer_tokens,
    state_machine_builder_for_sns_tests,
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    AccountIdentifier, LedgerCanisterInitPayload as IcpInitArgs, DEFAULT_TRANSFER_FEE,
};
use icrc_ledger_types::icrc1::{
    account::{Account, Subaccount},
    transfer::{Memo, TransferArg},
};
use lazy_static::lazy_static;
use std::{
    sync::{Arc, Mutex},
    thread,
};

lazy_static! {
    pub static ref DEFAULT_MINTING_ACCOUNT: Account = Account {
        owner: PrincipalId::new_user_test_id(1000).0,
        subaccount: None,
    };
    pub static ref DEFAULT_INITIAL_BALANCE: u64 = 10_000_000;
    pub static ref DEFAULT_ICP_LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(0);
    pub static ref DEFAULT_ICRC1_LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(1);
    pub static ref DEFAULT_SNS_SALE_CANISTER_ID: CanisterId = CanisterId::from_u64(2);
    pub static ref DEFAULT_NNS_GOVERNANCE_PRINCIPAL: Principal = Principal::anonymous();
    pub static ref DEFAULT_SNS_GOVERNANCE_PRINCIPAL: Principal = Principal::anonymous();
    pub static ref DEFAULT_SNS_ROOT_PRINCIPAL: Principal = Principal::anonymous();
    pub static ref DEFAULT_FALLBACK_CONTROLLER_PRINCIPAL_IDS: Vec<Principal> =
        vec![Principal::anonymous()];
    pub static ref DEFAULT_NEURON_MINIMUM_STAKE: u64 = 400_000;
    pub static ref DEFAULT_ICRC1_ARCHIVE_OPTIONS: ArchiveOptions = ArchiveOptions {
        trigger_threshold: 1,
        num_blocks_to_archive: 1,
        node_max_memory_size_bytes: None,
        max_message_size_bytes: None,
        controller_id: PrincipalId::new_anonymous(),
        more_controller_ids: None,
        cycles_for_archive_creation: None,
        max_transactions_per_response: None,
    };
}

pub struct PaymentProtocolTestSetup {
    pub state_machine: StateMachine,
    pub sns_sale_canister_id: CanisterId,
    pub icp_ledger_canister_id: CanisterId,
    pub icp_ledger_minting_account: Account,
}

impl PaymentProtocolTestSetup {
    /// If no specific initialization arguments need to be used for a test, the default versions can be used by parsing None
    /// for all init args.
    pub fn default_setup() -> Self {
        let state_machine = state_machine_builder_for_sns_tests().build();
        let icp_ledger_id = state_machine.create_canister(None);
        let sns_ledger_id = state_machine.create_canister(None);
        let swap_id = state_machine.create_canister(None);

        // Make sure the created canisters all have the correct ID
        assert!(icp_ledger_id == *DEFAULT_ICP_LEDGER_CANISTER_ID);
        assert!(sns_ledger_id == *DEFAULT_ICRC1_LEDGER_CANISTER_ID);
        assert!(swap_id == *DEFAULT_SNS_SALE_CANISTER_ID);

        // install the ICP ledger
        {
            let wasm = ic_test_utilities_load_wasm::load_wasm(
                "../../rosetta-api/icp_ledger/ledger",
                "ledger-canister",
                &[],
            );
            let args = Encode!(&PaymentProtocolTestSetup::default_icp_init_args()).unwrap();
            state_machine
                .install_existing_canister(icp_ledger_id, wasm, args)
                .unwrap();
        }
        // install the sns ledger
        {
            let wasm = ic_test_utilities_load_wasm::load_wasm(
                "../../rosetta-api/icrc1/ledger",
                "ic-icrc1-ledger",
                &[],
            );
            let args = Encode!(&LedgerArgument::Init(
                PaymentProtocolTestSetup::default_icrc1_init_args()
            ))
            .unwrap();
            state_machine
                .install_existing_canister(sns_ledger_id, wasm, args)
                .unwrap();
        }

        // install the sale canister
        {
            let wasm = ic_test_utilities_load_wasm::load_wasm("../swap", "sns-swap-canister", &[]);
            let args = Encode!(&PaymentProtocolTestSetup::default_sns_sale_init_args()).unwrap();

            state_machine
                .install_existing_canister(swap_id, wasm, args)
                .unwrap();
        }

        Self {
            state_machine,
            sns_sale_canister_id: swap_id,
            icp_ledger_canister_id: icp_ledger_id,
            icp_ledger_minting_account: *DEFAULT_MINTING_ACCOUNT,
        }
    }

    pub fn default_icp_init_args() -> IcpInitArgs {
        IcpInitArgs::builder()
            .minting_account(AccountIdentifier::from(*DEFAULT_MINTING_ACCOUNT))
            .icrc1_minting_account(*DEFAULT_MINTING_ACCOUNT)
            .transfer_fee(DEFAULT_TRANSFER_FEE)
            .token_symbol_and_name("Internet Computer", "ICP")
            .build()
            .unwrap()
    }
    pub fn default_icrc1_init_args() -> Icrc1InitArgs {
        ic_icrc1_ledger::InitArgsBuilder::with_symbol_and_name("STK", "SNS Token")
            .with_minting_account(*DEFAULT_MINTING_ACCOUNT)
            .with_transfer_fee(DEFAULT_TRANSFER_FEE)
            .with_archive_options(DEFAULT_ICRC1_ARCHIVE_OPTIONS.clone())
            .with_initial_balance(
                DEFAULT_SNS_SALE_CANISTER_ID.get().0,
                *DEFAULT_INITIAL_BALANCE,
            )
            .build()
    }

    pub fn default_sns_sale_init_args() -> Init {
        Init {
            nns_governance_canister_id: (*DEFAULT_NNS_GOVERNANCE_PRINCIPAL).to_string(),
            sns_governance_canister_id: (*DEFAULT_SNS_GOVERNANCE_PRINCIPAL).to_string(),
            sns_ledger_canister_id: (*DEFAULT_ICRC1_LEDGER_CANISTER_ID).to_string(),
            icp_ledger_canister_id: (*DEFAULT_ICP_LEDGER_CANISTER_ID).to_string(),
            sns_root_canister_id: (*DEFAULT_SNS_ROOT_PRINCIPAL).to_string(),
            fallback_controller_principal_ids: DEFAULT_FALLBACK_CONTROLLER_PRINCIPAL_IDS
                .clone()
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
            transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
            neuron_minimum_stake_e8s: Some(*DEFAULT_NEURON_MINIMUM_STAKE),
            confirmation_text: None,
            restricted_countries: None,
            min_participants: Some(1),
            min_direct_participation_icp_e8s: Some(1),
            max_direct_participation_icp_e8s: Some(10_000_000),
            min_participant_icp_e8s: Some(1_010_000),
            max_participant_icp_e8s: Some(10_000_000),
            sns_token_e8s: Some(10_000_000),
            swap_start_timestamp_seconds: Some(0),
            swap_due_timestamp_seconds: Some(
                state_machine_builder_for_sns_tests()
                    .build()
                    .time()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 13 * ONE_DAY_SECONDS,
            ),
            neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                count: 2,
                dissolve_delay_interval_seconds: 1,
            }),
            nns_proposal_id: Some(10),
            should_auto_finalize: Some(true),
            max_icp_e8s: None,
            min_icp_e8s: None,
            neurons_fund_participation_constraints: None,
            neurons_fund_participation: None,
        }
    }

    pub fn mint_icp(&self, account: &Account, amount: &u64) -> Result<u64, String> {
        icrc1_transfer(
            &self.state_machine,
            self.icp_ledger_canister_id,
            PrincipalId(self.icp_ledger_minting_account.owner),
            TransferArg {
                from_subaccount: None,
                to: *account,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(*amount),
            },
        )
    }

    pub fn commit_icp_e8s(&self, sender: &PrincipalId, ticket: &Ticket) -> Result<u64, String> {
        let sns_sale_principal_id: PrincipalId = self.sns_sale_canister_id.into();
        icrc1_transfer(
            &self.state_machine,
            self.icp_ledger_canister_id,
            *sender,
            TransferArg {
                from_subaccount: None,
                to: Account {
                    owner: sns_sale_principal_id.0,
                    subaccount: Some(principal_to_subaccount(sender)),
                },
                fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                created_at_time: Some(ticket.clone().creation_time),
                memo: None,
                amount: Nat::from(ticket.clone().amount_icp_e8s),
            },
        )
    }

    pub fn transfer_icp(
        &self,
        from: &PrincipalId,
        from_subaccount: Option<Subaccount>,
        to: &Account,
        created_at_time: Option<u64>,
        memo: Option<Memo>,
        amount: &u64,
    ) -> Result<u64, String> {
        icrc1_transfer(
            &self.state_machine,
            self.icp_ledger_canister_id,
            *from,
            TransferArg {
                from_subaccount,
                to: *to,
                fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                created_at_time,
                memo,
                amount: Nat::from(*amount),
            },
        )
    }
    pub fn get_buyer_state(&self, buyer: &PrincipalId) -> Option<BuyerState> {
        get_buyer_state(&self.state_machine, &self.sns_sale_canister_id, buyer).buyer_state
    }

    pub fn get_buyers_total(&self) -> u64 {
        get_buyers_total(&self.state_machine, &self.sns_sale_canister_id).buyers_total
    }

    pub fn get_sns_sale_parameters(&self) -> Params {
        get_sns_sale_parameters(&self.state_machine, &self.sns_sale_canister_id)
            .params
            .unwrap()
    }

    pub fn refresh_buyer_tokens(
        &self,
        buyer: &PrincipalId,
        confirmation_text: Option<String>,
    ) -> Result<RefreshBuyerTokensResponse, String> {
        refresh_buyer_tokens(
            &self.state_machine,
            &self.sns_sale_canister_id,
            buyer,
            confirmation_text,
        )
    }

    pub fn get_lifecycle(&self) -> GetLifecycleResponse {
        get_lifecycle(&self.state_machine, &self.sns_sale_canister_id)
    }

    pub fn get_open_ticket(&self, buyer: &PrincipalId) -> Result<Option<Ticket>, i32> {
        get_open_ticket(&self.state_machine, self.sns_sale_canister_id, *buyer).ticket()
    }

    pub fn new_sale_ticket(
        &self,
        buyer: &PrincipalId,
        amount_icp_e8s: &u64,
        subaccount: Option<Vec<u8>>,
    ) -> Result<Ticket, new_sale_ticket_response::Err> {
        new_sale_ticket(
            &self.state_machine,
            self.sns_sale_canister_id,
            *buyer,
            *amount_icp_e8s,
            subaccount,
        )
    }
    pub fn notify_payment_failure(&self, sender: &PrincipalId) -> Option<Ticket> {
        notify_payment_failure(&self.state_machine, &self.sns_sale_canister_id, sender).ticket
    }
}

#[test]
fn test_get_open_ticket() {
    let user0 = PrincipalId::new_user_test_id(0);
    let payment_flow_protocol = PaymentProtocolTestSetup::default_setup();
    assert_eq!(payment_flow_protocol.get_open_ticket(&user0).unwrap(), None);
}

#[test]
fn test_new_sale_ticket() {
    let user0 = PrincipalId::new_user_test_id(0);
    let user1 = PrincipalId::new_user_test_id(1);
    let payment_flow_protocol = PaymentProtocolTestSetup::default_setup();
    let params = payment_flow_protocol.get_sns_sale_parameters();
    // error when caller is anonymous
    assert_eq!(
        NewSaleTicketResponse {
            result: Some(ic_sns_swap::pb::v1::new_sale_ticket_response::Result::Err(
                payment_flow_protocol
                    .new_sale_ticket(
                        &PrincipalId::new_anonymous(),
                        &params.min_participant_icp_e8s,
                        None
                    )
                    .unwrap_err()
            ))
        },
        NewSaleTicketResponse::err_invalid_principal()
    );

    // error when subaccount is not 32 bytes
    assert_eq!(
        NewSaleTicketResponse {
            result: Some(ic_sns_swap::pb::v1::new_sale_ticket_response::Result::Err(
                payment_flow_protocol
                    .new_sale_ticket(&user0, &params.min_participant_icp_e8s, Some(vec![0; 31]))
                    .unwrap_err()
            ))
        },
        NewSaleTicketResponse::err_invalid_subaccount()
    );
    assert_eq!(
        NewSaleTicketResponse {
            result: Some(ic_sns_swap::pb::v1::new_sale_ticket_response::Result::Err(
                payment_flow_protocol
                    .new_sale_ticket(&user0, &params.min_participant_icp_e8s, Some(vec![0; 33]))
                    .unwrap_err()
            ))
        },
        NewSaleTicketResponse::err_invalid_subaccount()
    );

    // error when amount < min_participant_icp_e8s
    let res =
        payment_flow_protocol.new_sale_ticket(&user0, &(params.min_participant_icp_e8s - 1), None);
    let expected = NewSaleTicketResponse::err_invalid_user_amount(
        params.min_participant_icp_e8s,
        params.max_participant_icp_e8s,
    );
    assert_eq!(
        NewSaleTicketResponse {
            result: Some(new_sale_ticket_response::Result::Err(res.unwrap_err()))
        },
        expected
    );

    // error when amount > max_participant_icp_e8s
    let res =
        payment_flow_protocol.new_sale_ticket(&user0, &(params.max_participant_icp_e8s + 1), None);
    let expected = NewSaleTicketResponse::err_invalid_user_amount(
        params.min_participant_icp_e8s,
        params.max_participant_icp_e8s,
    );
    assert_eq!(
        NewSaleTicketResponse {
            result: Some(new_sale_ticket_response::Result::Err(res.unwrap_err()))
        },
        expected
    );

    // ticket correctly created
    let ticket = payment_flow_protocol
        .new_sale_ticket(&user0, &(params.min_participant_icp_e8s), None)
        .unwrap();

    // Ticket id counter starts with 0
    assert!(ticket.ticket_id == 0);

    // ticket can be retrieved
    let ticket_0 = payment_flow_protocol
        .get_open_ticket(&user0)
        .unwrap()
        .unwrap();

    // Make sure a new ticket cannot be created after the prior ticket was deleted
    let res =
        payment_flow_protocol.new_sale_ticket(&user0, &(params.min_participant_icp_e8s + 1), None);
    assert_eq!(
        NewSaleTicketResponse {
            result: Some(new_sale_ticket_response::Result::Err(res.unwrap_err()))
        },
        NewSaleTicketResponse::err_ticket_exists(ticket)
    );

    // ticket is still the same as before the error
    assert_eq!(
        payment_flow_protocol
            .get_open_ticket(&user0)
            .unwrap()
            .unwrap(),
        ticket_0
    );

    // Create new ticket for other user
    let ticket = payment_flow_protocol
        .new_sale_ticket(&user1, &(params.min_participant_icp_e8s), None)
        .unwrap();
    // Ticket id counter should now be at 1
    assert!(ticket.ticket_id == 1);

    // Make sure the ticket form user1 has an incremented ticket id
    let ticket_1 = payment_flow_protocol
        .get_open_ticket(&user1)
        .unwrap()
        .unwrap();
    assert!(ticket_1.ticket_id > ticket_0.ticket_id);

    // Test manual deleting ticket
    {
        // Make sure that there exists not ticket for the user0
        let deleted_ticket = payment_flow_protocol.notify_payment_failure(&user0);
        assert!(deleted_ticket.clone().unwrap().ticket_id == ticket_0.ticket_id);
        assert!(deleted_ticket.unwrap().ticket_id != ticket_1.ticket_id);
        let no_ticket_found = payment_flow_protocol.notify_payment_failure(&user0);
        assert!(no_ticket_found.is_none());

        // Make sure that there exists not ticket for the user1
        let deleted_ticket = payment_flow_protocol.notify_payment_failure(&user1);
        assert!(deleted_ticket.clone().unwrap().ticket_id == ticket_1.ticket_id);
        assert!(deleted_ticket.unwrap().ticket_id != ticket_0.ticket_id);
        let no_ticket_found = payment_flow_protocol.notify_payment_failure(&user1);
        assert!(no_ticket_found.is_none());
    }
}

#[test]
fn test_simple_refresh_buyer_token() {
    let user0 = PrincipalId::new_user_test_id(0);
    let payment_flow_protocol = PaymentProtocolTestSetup::default_setup();

    // Lifecycle of Swap should be Open
    assert_eq!(
        payment_flow_protocol.get_lifecycle().lifecycle,
        Some(Lifecycle::Open as i32)
    );

    let params = payment_flow_protocol.get_sns_sale_parameters();
    // Amount bought by user 0 amountx_y being the amount bought by user x with a counter y counting the number of purchases.
    let amount0_0 = params.min_participant_icp_e8s;

    // Get user0 some funds to participate in the sale
    assert!(payment_flow_protocol
        .mint_icp(&user0.0.into(), &(100 * E8))
        .is_ok());

    // Get a ticket
    assert!(payment_flow_protocol
        .new_sale_ticket(&user0, &amount0_0, None)
        .is_ok());

    // Commit some ICP
    payment_flow_protocol
        .commit_icp_e8s(
            &user0,
            &payment_flow_protocol
                .get_open_ticket(&user0)
                .unwrap()
                .unwrap(),
        )
        .unwrap();

    // Get ICP accepted by the SNS sale canister
    assert!(payment_flow_protocol
        .refresh_buyer_tokens(&user0, None)
        .is_ok());

    // Check that the buyer state was updated accordingly
    assert_eq!(
        payment_flow_protocol
            .get_buyer_state(&user0)
            .unwrap()
            .icp
            .unwrap()
            .amount_e8s,
        amount0_0.clone()
    );

    // Check that the ticket has been deleted
    assert!(payment_flow_protocol
        .get_open_ticket(&user0)
        .unwrap()
        .is_none())
}

#[test]
fn test_multiple_payment_flows() {
    let user0 = PrincipalId::new_user_test_id(0);
    let payment_flow_protocol = PaymentProtocolTestSetup::default_setup();

    // Lifecycle of Swap should be Open
    assert_eq!(
        payment_flow_protocol.get_lifecycle().lifecycle,
        Some(Lifecycle::Open as i32)
    );

    let params = payment_flow_protocol.get_sns_sale_parameters();
    let amount0_0 = params.min_participant_icp_e8s;

    // Get user0 some funds to participate in the sale
    assert!(payment_flow_protocol
        .mint_icp(&user0.0.into(), &(100 * E8))
        .is_ok());

    let mut amount_committed = 0;

    for _ in 0..3 {
        // Step 1: Get a ticket
        assert!(payment_flow_protocol
            .new_sale_ticket(&user0, &amount0_0, None)
            .is_ok());

        // Step 2: Commit some ICP
        payment_flow_protocol
            .commit_icp_e8s(
                &user0,
                &payment_flow_protocol
                    .get_open_ticket(&user0)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();

        // Step3: Get ICP accepted by the SNS sale canister
        assert!(payment_flow_protocol
            .refresh_buyer_tokens(&user0, None)
            .is_ok());
        amount_committed += amount0_0;

        // Step 4: Check that the buyer state was updated accordingly
        assert_eq!(
            payment_flow_protocol
                .get_buyer_state(&user0)
                .unwrap()
                .icp
                .unwrap()
                .amount_e8s,
            amount_committed.clone()
        );

        // Check that the ticket has been deleted
        assert!(payment_flow_protocol
            .get_open_ticket(&user0)
            .unwrap()
            .is_none())
    }
}

#[test]
fn test_payment_flow_multiple_users_concurrent() {
    let mut users = vec![];
    let mut handles = vec![];
    let payment_flow_protocol = Arc::new(Mutex::new(PaymentProtocolTestSetup::default_setup()));

    // Lifecycle of Swap should be Open
    assert_eq!(
        payment_flow_protocol
            .lock()
            .unwrap()
            .get_lifecycle()
            .lifecycle,
        Some(Lifecycle::Open as i32)
    );

    let params = payment_flow_protocol
        .lock()
        .unwrap()
        .get_sns_sale_parameters();

    // Get users some funds to participate in the sale
    for i in 0..5 {
        let new_user = PrincipalId::new_user_test_id(i);
        users.push(new_user);
        assert!(payment_flow_protocol
            .lock()
            .unwrap()
            .mint_icp(&new_user.0.into(), &(100 * E8))
            .is_ok());
    }

    fn execute_payment_flow(
        user: PrincipalId,
        payment_flow_protocol: Arc<Mutex<PaymentProtocolTestSetup>>,
        amount: u64,
    ) {
        // Get a ticket
        let ticket = payment_flow_protocol
            .lock()
            .unwrap()
            .new_sale_ticket(&user, &amount, None);

        // Commit some ICP
        payment_flow_protocol
            .lock()
            .unwrap()
            .commit_icp_e8s(&user, &ticket.unwrap())
            .unwrap();

        // Get ICP accepted by the SNS sale canister
        assert!(payment_flow_protocol
            .lock()
            .unwrap()
            .refresh_buyer_tokens(&user, None)
            .is_ok());

        // Check that the buyer state was updated accordingly
        assert_eq!(
            payment_flow_protocol
                .lock()
                .unwrap()
                .get_buyer_state(&user)
                .unwrap()
                .icp
                .unwrap()
                .amount_e8s,
            amount.clone()
        );

        // Check that the ticket has been deleted
        assert!(payment_flow_protocol
            .lock()
            .unwrap()
            .get_open_ticket(&user)
            .unwrap()
            .is_none());
    }

    for user in users.clone() {
        let payment_flow_protocol = Arc::clone(&payment_flow_protocol);
        let handle = thread::spawn(move || {
            execute_payment_flow(user, payment_flow_protocol, params.min_participant_icp_e8s)
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Check that the total amount of ICP spent is as expected
    assert_eq!(
        payment_flow_protocol.lock().unwrap().get_buyers_total(),
        params.min_participant_icp_e8s * (users.len() as u64)
    );
    // Check that every user has the minimum amount deposited
    for user in users.clone() {
        assert_eq!(
            payment_flow_protocol
                .lock()
                .unwrap()
                .get_buyer_state(&user)
                .unwrap()
                .icp
                .unwrap()
                .amount_e8s,
            params.min_participant_icp_e8s.clone()
        );
    }
}

#[test]
fn test_multiple_spending() {
    let user0 = PrincipalId::new_user_test_id(0);
    let payment_flow_protocol = PaymentProtocolTestSetup::default_setup();

    // Lifecycle of Swap should be Open
    assert_eq!(
        payment_flow_protocol.get_lifecycle().lifecycle,
        Some(Lifecycle::Open as i32)
    );

    let params = payment_flow_protocol.get_sns_sale_parameters();
    let amount0_0 = params.min_participant_icp_e8s;

    // Get user0 some funds to participate in the sale
    assert!(payment_flow_protocol
        .mint_icp(&user0.0.into(), &(100 * E8))
        .is_ok());

    // Get a ticket
    assert!(payment_flow_protocol
        .new_sale_ticket(&user0, &amount0_0, None)
        .is_ok());

    // Commit some ICP
    let idx = payment_flow_protocol
        .commit_icp_e8s(
            &user0,
            &payment_flow_protocol
                .get_open_ticket(&user0)
                .unwrap()
                .unwrap(),
        )
        .unwrap();

    // Try to buy some more tokens with same ticket parameters --> Should fail due to multiple spending error
    assert!(payment_flow_protocol
        .commit_icp_e8s(
            &user0,
            &payment_flow_protocol
                .get_open_ticket(&user0)
                .unwrap()
                .unwrap()
        )
        .unwrap_err()
        .contains(&format!("duplicate_of: Nat({})", idx)),);

    // Get ICP accepted by the SNS sale canister
    assert!(payment_flow_protocol
        .refresh_buyer_tokens(&user0, None)
        .is_ok());

    // Check that the buyer state was updated accordingly
    assert_eq!(
        payment_flow_protocol
            .get_buyer_state(&user0)
            .unwrap()
            .icp
            .unwrap()
            .amount_e8s,
        amount0_0.clone()
    );

    // Check that the ticket has been deleted
    assert!(payment_flow_protocol
        .get_open_ticket(&user0)
        .unwrap()
        .is_none())
}

#[test]
fn test_maximum_reached() {
    let user0 = PrincipalId::new_user_test_id(0);
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);

    let payment_flow_protocol = PaymentProtocolTestSetup::default_setup();

    // Lifecycle of Swap should be Open
    assert_eq!(
        payment_flow_protocol.get_lifecycle().lifecycle,
        Some(Lifecycle::Open as i32)
    );

    let params = payment_flow_protocol.get_sns_sale_parameters();
    let amount0_0 = params.min_participant_icp_e8s;
    let amount1_0 = params.min_participant_icp_e8s;
    let amount2_0 = params.max_participant_icp_e8s;

    // Check that the amount bought by the three users exceeds the maximum amount of icp being available for sale (User2 is transferring more than there are tokens left after user0 and user1 have bought)
    assert!(amount1_0 + amount0_0 + amount2_0 > params.max_icp_e8s);

    // User2 should be able to make a purchase
    assert!(amount2_0 >= params.min_participant_icp_e8s);

    // Get users some funds to participate in the sale
    assert!(payment_flow_protocol
        .mint_icp(&user0.0.into(), &(100 * E8))
        .is_ok());
    // Get users some funds to participate in the sale
    assert!(payment_flow_protocol
        .mint_icp(&user1.0.into(), &(100 * E8))
        .is_ok());
    // Get users some funds to participate in the sale
    assert!(payment_flow_protocol
        .mint_icp(&user2.0.into(), &(100 * E8))
        .is_ok());
    let execute_payment_flow =
        |user: &PrincipalId, payment_flow_protocol: &PaymentProtocolTestSetup, amount: &u64| {
            // Get a ticket
            assert!(payment_flow_protocol
                .new_sale_ticket(user, amount, None)
                .is_ok());

            // Commit some ICP
            payment_flow_protocol
                .commit_icp_e8s(
                    user,
                    &payment_flow_protocol
                        .get_open_ticket(user)
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();

            // Get ICP accepted by the SNS sale canister
            assert!(payment_flow_protocol
                .refresh_buyer_tokens(user, None)
                .is_ok());

            // Check that the ticket has been deleted
            assert!(payment_flow_protocol
                .get_open_ticket(&user0)
                .unwrap()
                .is_none())
        };

    execute_payment_flow(&user0, &payment_flow_protocol, &amount0_0);
    execute_payment_flow(&user1, &payment_flow_protocol, &amount1_0);
    execute_payment_flow(&user2, &payment_flow_protocol, &amount2_0);

    assert_eq!(payment_flow_protocol.get_buyers_total(), params.max_icp_e8s);
    assert_eq!(
        payment_flow_protocol
            .get_buyer_state(&user0)
            .unwrap()
            .icp
            .unwrap()
            .amount_e8s,
        amount0_0.clone()
    );
    assert_eq!(
        payment_flow_protocol
            .get_buyer_state(&user1)
            .unwrap()
            .icp
            .unwrap()
            .amount_e8s,
        amount1_0.clone()
    );
    assert_eq!(
        payment_flow_protocol
            .get_buyer_state(&user2)
            .unwrap()
            .icp
            .unwrap()
            .amount_e8s,
        (params.max_icp_e8s - (amount0_0 + amount1_0))
    )
}

#[test]
fn test_commitment_below_participant_minimum() {
    let user0 = PrincipalId::new_user_test_id(0);
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let users = vec![user0, user1, user2];

    let payment_flow_protocol = PaymentProtocolTestSetup::default_setup();

    // Lifecycle of Swap should be Open
    assert_eq!(
        payment_flow_protocol.get_lifecycle().lifecycle,
        Some(Lifecycle::Open as i32)
    );

    let params = payment_flow_protocol.get_sns_sale_parameters();
    println!("Sale parameters: {:?}", params);
    let amount0_0 = (params.max_participant_icp_e8s - 1) / 2;
    let amount1_0 = (params.max_participant_icp_e8s - 1) / 2;
    let amount2_0 = params.min_participant_icp_e8s;
    let amount0_1 = params.min_participant_icp_e8s;

    // Make sure that the maximum can be reached with the contributions of user0 and user1
    assert!(amount0_0 + amount0_1 + amount1_0 > params.max_icp_e8s);

    // Make sure that the amount to be topped up at the end is less than the minimum that can be topped up per user
    assert!(
        params.max_participant_icp_e8s - (amount0_0 + amount1_0) < params.min_participant_icp_e8s
    );

    // There must be some tokens left in the sale although be it below the minimum per user
    assert!(params.max_icp_e8s - (amount0_0 + amount1_0) > 0);

    for user in &users {
        // Get users some funds to participate in the sale
        assert!(payment_flow_protocol
            .mint_icp(
                &Account {
                    owner: user.0,
                    subaccount: None
                },
                &(100 * E8)
            )
            .is_ok());
    }

    assert_eq!(
        payment_flow_protocol.get_lifecycle().lifecycle,
        Some(Lifecycle::Open as i32)
    );

    // Conduct payment flow for user0 and user1
    payment_flow_protocol
        .commit_icp_e8s(
            &user0,
            &payment_flow_protocol
                .new_sale_ticket(&user0, &amount0_0, None)
                .unwrap(),
        )
        .unwrap();
    assert!(payment_flow_protocol
        .refresh_buyer_tokens(&user0, None)
        .is_ok());

    payment_flow_protocol
        .commit_icp_e8s(
            &user1,
            &payment_flow_protocol
                .new_sale_ticket(&user1, &amount1_0, None)
                .unwrap(),
        )
        .unwrap();
    assert!(payment_flow_protocol
        .refresh_buyer_tokens(&user1, None)
        .is_ok());

    // The amount bought now should be below the maximum and the amount left should be less than the minimum per participant
    assert!(
        payment_flow_protocol.get_buyers_total() <= params.max_icp_e8s
            && params.max_icp_e8s - payment_flow_protocol.get_buyers_total()
                < params.min_participant_icp_e8s
    );

    let sns_sale_principal_id: PrincipalId = payment_flow_protocol.sns_sale_canister_id.into();

    // User2 who has not yet participated in the sale should not be able to purchase the missing tokens
    payment_flow_protocol
        .transfer_icp(
            &user2,
            None,
            &Account {
                owner: sns_sale_principal_id.0,
                subaccount: Some(principal_to_subaccount(&user2)),
            },
            None,
            None,
            &amount2_0,
        )
        .unwrap();
    assert!(payment_flow_protocol
        .refresh_buyer_tokens(&user2, None)
        .is_err());

    // User0 who has participated in the sale should be able to purchase the missing tokens
    payment_flow_protocol
        .commit_icp_e8s(
            &user0,
            &payment_flow_protocol
                .new_sale_ticket(&user0, &amount0_1, None)
                .unwrap(),
        )
        .unwrap();
    assert!(payment_flow_protocol
        .refresh_buyer_tokens(&user0, None)
        .is_ok());

    //Check that user1's purchase was registered
    assert_eq!(
        payment_flow_protocol
            .get_buyer_state(&user1)
            .unwrap()
            .icp
            .unwrap()
            .amount_e8s,
        amount1_0.clone()
    );

    // Check that user2's purchase was not registered
    assert!(payment_flow_protocol.get_buyer_state(&user2).is_none());

    // Check that user0's purchase was registered and that he has bought the tokens left in the sale
    assert_eq!(
        payment_flow_protocol
            .get_buyer_state(&user0)
            .unwrap()
            .icp
            .unwrap()
            .amount_e8s,
        params.max_participant_icp_e8s - amount1_0
    );

    // Check that the maximum of purchased tokens has been reached
    assert_eq!(payment_flow_protocol.get_buyers_total(), params.max_icp_e8s);
}
