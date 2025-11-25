---- MODULE Update_Balance_Apalache ----

EXTENDS Apalache, TypeAliases

\* CODE_LINK_INSERT_CONSTANTS

(*
CONSTANTS
    \* @type: Set($principal);
    PRINCIPALS,
    \* @type: Set($subaccount);
    SUBACCOUNTS,
    \* @type: $principal;
    MINTER_PRINCIPAL,
    \* @type: $subaccount;
    MINTER_SUBACCOUNT,
    \* @type: Set($pid);
    UPDATE_BALANCE_PROCESS_IDS,
    \* @type: $ckbtcAddress -> $btcAddress;
    DEPOSIT_ADDRESS,
    \* @type: $txHashOp;
    TX_HASH_OP,
    \* @type: $value;
    CHECK_FEE
*)

VARIABLES
          \* @type: $ckbtcAddress -> Set($utxo);
          utxos_state_addresses,
          \* @type: Set($utxo);
          available_utxos,
          \* @type: $principal -> Set($utxo);
          finalized_utxos,
          \* @type: Set($principal);
          update_balance_locks,
          \* @type: Set($principal);
          retrieve_btc_locks,
          \* @type: Set($principal);
          locks,
          \* @type: Seq($withdrawalReq);
          pending,
          \* @type: Set($submittedTx);
          submitted_transactions,
          \* @type: Seq($minterToBtcCanisterRequest);
          minter_to_btc_canister,
          \* @type: Set($btcCanisterToMinterResponse);
          btc_canister_to_minter,
          \* @type: Seq($minterToLedgerRequest);
          minter_to_ledger,
          \* @type: Set($ledgerToMinterResponse);
          ledger_to_minter,
          \* @type: $pid -> $ckbtcAddress;
          caller_account,
          \* @type: $pid -> Set($utxo);
          utxos,
          \* @type: $pid -> $utxo;
          utxo,
          \* @type: $pc;
          pc

UB == INSTANCE Update_Balance

Init == UB!Init
Next == UB!Next
vars == UB!vars

Spec == Init /\ [][Next]_vars

====
