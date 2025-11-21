---- MODULE CkbtcMinter_Apalache ----

EXTENDS TLC, Sequences, FiniteSets, TypeAliases

\* CODE_LINK_INSERT_CONSTANTS

CONSTANTS
    \* @type: Set($principal);
    PRINCIPALS,
    \* @type: Set($subaccount);
    SUBACCOUNTS,
    \* @type: $principal;
    MINTER_PRINCIPAL,
    \* @type: $subaccount;
    MINTER_SUBACCOUNT,
    \* @type: Int;
    MAX_USER_BTC_TRANSFERS,
    \* @type: $amount;
    BTC_SUPPLY,
    \* @type: $amount;
    MINTER_INITIAL_SUPPLY,
    \* @type: Set($pid);
    UPDATE_BALANCE_PROCESS_IDS,
    \* @type: Set($pid);
    RETRIEVE_BTC_PROCESS_IDS,
    \* @type: Set($pid);
    RESUBMIT_RETRIEVE_BTC_PROCESS_IDS,
    \* @type: $btcAddress;
    USER_BTC_ADDRESS,
    \* @type: $pid;
    BTC_PROCESS_ID,
    \* @type: $pid;
    LEDGER_PROCESS_ID,
    \* @type: $pid;
    BTC_CANISTER_PROCESS_ID,
    \* @type: Set($pid);
    HEARTBEAT_PROCESS_IDS,
    \* @type: $amount;
    RETRIEVE_BTC_FEE,
    \* @type: $ckbtcAddress -> $btcAddress;
    DEPOSIT_ADDRESS

(*
@typeAlias: requestId = Int;
*)
_dummy == TRUE

VARIABLES
    \* @type: Set($utxo);
    btc,
    \* @type: Set($utxo);
    btc_canister,
    \* @type: $ckbtcAddress -> Set($utxo);
    utxos_state_addresses,
    \* @type: Set($principal);
    locks,
    \* @type: $ckbtcAddress -> $amount;
    balance,
    \* @type: Set($submission);
    btc_canister_to_btc,
    \* @type: Seq($minterToBtcCanisterRequest);
    minter_to_btc_canister,
    \* @type: Set($btcCanisterToMinterResponse);
    btc_canister_to_minter,
    \* @type: Seq($minterToLedgerRequest);
    minter_to_ledger,
    \* @type: Set($ledgerToMinterResponse);
    ledger_to_minter,
    \* @type: Int;
    next_request_id,
    \* @type: Int;
    resubmit_count,
    \* @type: $pc;
    pc,
    \* @type: $pid -> Seq($withdrawalReq);
    submitted,
    \* @type: $pid -> Seq($requestId);
    submitted_ids,
    \* @type: $pid -> Set($utxo);
    spent,
    \* @type: $pid -> Seq({ owner: $btcAddress, amount: $amount});
    outputs,
    \* @type: Int;
    nr_user_transfers,
    \* @type: $pid -> $amount;
    amount,
    \* @type: $pid -> $ckbtcAddress;
    caller_account,
    \* @type: $pid -> Set($utxo);
    new_utxos,
    \* @type: $pid -> $optSubmission;
    new_transaction,
    \* @type: Seq($withdrawalReq);
    pending,
    \* @type: $principal -> Set($utxo);
    finalized_utxos,
    \* @type: Set($utxo);
    available_utxos,
    \* @type: Set($submittedTx);
    submitted_transactions

INSTANCE CkbtcMinter


====
