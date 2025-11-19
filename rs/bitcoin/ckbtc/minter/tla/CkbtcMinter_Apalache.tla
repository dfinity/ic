---- MODULE CkbtcMinter_Apalache ----

EXTENDS TLC, Sequences, FiniteSets

\* CODE_LINK_INSERT_CONSTANTS

(*
@typeAlias: btc_address = Str;
@typeAlias: pid = Str;
@typeAlias: utxo = {id: Seq(Int), owner: $btc_address, amount: Int};
@typeAlias: withdrawal_req = {request_id: Int, address: $btc_address, amount: Int};
@typeAlias: submission = {consumed_utxos: Set($utxo), outputs: Seq({owner: $btc_address, amount: Int}), other_data: Int};
*)

CONSTANTS 
    \* @type: Set(Str);
    CK_BTC_ADDRESSES,
    \* @type: Int;
    MAX_USER_BTC_TRANSFERS,
    \* @type: Int;
    BTC_SUPPLY,
    \* @type: Set($pid);
    UPDATE_BALANCE_PROCESS_IDS,
    \* @type: Set($pid);
    RETRIEVE_BTC_PROCESS_IDS,
    \* @type: Set($pid);
    RESUBMIT_RETRIEVE_BTC_PROCESS_IDS,
    \* @type: Str;
    USER_BTC_ADDRESS,
    \* @type: Str;
    MINTER_BTC_ADDRESS,
    \* @type: $pid;
    INGEST_BTC_STATE_PROCESS_ID,
    \* @type: Str;
    BTC_PROCESS_ID,
    \* @type: $pid;
    USER_CK_BTC_TRANSFER_PROCESS_ID,
    \* @type: $pid;
    LEDGER_PROCESS_ID,
    \* @type: $pid;
    BTC_CANISTER_PROCESS_ID,
    \* @type: $pid;
    HEARTBEAT_PROCESS_ID,
    \* Converts a user CK_BTC address to a withdrawal account on the ledger.
    \* @type: $btc_address => ;
    BTC_TO_WITHDRAWAL(_)

VARIABLES
    \* @type: Set(Int);
    btc,
    \* @type: Set(Int);
    btc_canister,
    \* @type: Int;
    utxos_states_addresses,
    \* @type: Set(Int);
    locks,
    \* @type: Seq(Int);
    pending_retrieve_btc_requests,
    \* @type: Int;
    requests_in_flight,
    \* @type: Int;
    balance,
    \* @type: Set(Int);
    btc_canister_to_btc,
    \* @type: Seq(Int);
    minter_to_btc_canister,
    \* @type: Set(Int);
    btc_canister_to_minter,
    \* @type: Seq(Int);
    minter_to_ledger,
    \* @type: Set(Int);
    ledger_to_minter,
    \* @type: Int;
    next_request_id,
    \* @type: Int;
    resubmit_count,
    \* @type: Str;
    pc,
    \* @type: Int;
    stack,
    \* @type: Int;
    submitted,
    \* @type: Int;
    spent,
    \* @type: Int;
    outputs,
    \* @type: Int;
    nr_user_transfers,
    \* @type: Int;
    ck_btc_address,
    \* @type: Int;
    amount,
    \* @type: Int;
    resubmit_request_id,
    \* @type: Int;
    resubmission

MOD == INSTANCE CkbtcMinter
    WITH
        btc <- btc,
        btc_canister <- btc_canister,
        utxos_states_addresses <- utxos_states_addresses,
        locks <- locks,
        pending_retrieve_btc_requests <- pending_retrieve_btc_requests,
        requests_in_flight <- requests_in_flight,
        balance <- balance,
        btc_canister_to_btc <- btc_canister_to_btc,
        minter_to_btc_canister <- minter_to_btc_canister,
        btc_canister_to_minter <- btc_canister_to_minter,
        minter_to_ledger <- minter_to_ledger,
        ledger_to_minter <- ledger_to_minter,
        next_request_id <- next_request_id,
        resubmit_count <- resubmit_count,
        pc <- pc,
        stack <- stack,
        submitted <- submitted,
        spent <- spent,
        outputs <- outputs,
        nr_user_transfers <- nr_user_transfers,
        ck_btc_address <- ck_btc_address,
        amount <- amount,
        resubmit_request_id <- resubmit_request_id,
        resubmission <- resubmission

ApalacheSpec == [MOD!Next]_MOD!vars

====
