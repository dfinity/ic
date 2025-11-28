---- MODULE Retrieve_BTC_Apalache ----

EXTENDS Apalache, TypeAliases, Variants, TLA_Hash

\* CODE_LINK_INSERT_CONSTANTS

(*
CONSTANTS
    \* @type: Set($principal);
    PRINCIPALS,
    \* @type: Set($subaccount);
    SUBACCOUNTS,
    \* @type: Set($pid);
    RETRIEVE_BTC_PROCESS_IDS,
    \* @type: Set($btcAddress);
    USER_BTC_ADDRESSES,
    \* @type: $value;
    BTC_SUPPLY,
    \* @type: $value;
    RETRIEVE_BTC_FEE,
    \* @type: $ckbtcAddress -> $btcAddress;
    DEPOSIT_ADDRESS,
    \* @type: $principal;
    MINTER_PRINCIPAL,
    \* @type: $subaccount;
    MINTER_SUBACCOUNT,
    \* @type: $txHashOp;
    TX_HASH_OP
*)

VARIABLES
          \* @type: $pc;
          pc,
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
          \* @type: $pid -> $value;
          amount

RB == INSTANCE Retrieve_BTC

Init == RB!Init
Next == RB!Next
vars == RB!vars

Spec == Init /\ [][Next]_vars

====
