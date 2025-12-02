---- MODULE Update_Balance ----
EXTENDS TLC, Sequences, Integers, FiniteSets, FiniteSetsExt, SequencesExt, Functions, Variants, Apalache, TLA_Hash, TypeAliases, Ckbtc_Common

CONSTANTS
    \* The set of process IDs for the update balance processes.
    \* The cardinality of the set effectively determines the number of concurrent calls
    \* to the update_balance method on the minter canister.
    UPDATE_BALANCE_PROCESS_IDS,
    CHECK_FEE,
    DEPOSIT_ADDRESS

Utxo_Ignored == "Ignored"
Utxo_OK == "OK"

DUMMY_UTXO == [ id |-> <<"x", 0>>, owner |-> "dummy_address", value |-> 0 ]

(* --algorithm update_balance {

variables
    \**********************************************************************************************
    \* BTC library state (part of the minter canister state)
    \**********************************************************************************************
    \* State of the minter
    utxos_state_addresses \in Empty_Funs;
    \* Available utxos
    available_utxos = {};
    \* Finalized utxos: utxos that are being finalized but their corresponding principal is still locked
    finalized_utxos \in Empty_Funs;
    \**********************************************************************************************
    \* The remaining minter state
    \**********************************************************************************************
    \* Currently locked ckBTC (user) addresses, for which balance update is in progress.
    \* Note that in the model we only have locks for updating balances, but not for retrieving
    \* BTC. The model doesn't find any errors arising from the missing retrieve BTC locks.
    update_balance_locks = {};
    retrieve_btc_locks = {};
    locks = {};
    \* The queue of pending submissions (initially, an empty sequence)
    pending = <<>>;
    \* The set of submitted transactions
    submitted_transactions = {};
    \* Buffers modelling in-flight inter-canister calls. The requests are stored
    \* in sequences (i.e., ordered collections), the responses in sets (unordered).
    \* This reflects the ordering guarantees of the IC.
    minter_to_btc_canister = <<>>;
    btc_canister_to_minter = {};
    minter_to_ledger = <<>>;
    ledger_to_minter = {};

macro return_from_update_balance() {
            update_balance_locks := update_balance_locks \ {caller_account.owner};
            caller_account := MINTER_CKBTC_ADDRESS;
            utxos := {};
            utxo := DUMMY_UTXO;
            goto Update_Balance_Start;
}

macro send_minter_to_btc_canister_get_utxos(caller_id, address) {
    minter_to_btc_canister := Append(minter_to_btc_canister,
        Get_Utxos_Request(caller_id, DEPOSIT_ADDRESS[address]));
}

\* A set of small auxiliary macros used for inter-canister calls
macro send_minter_to_ledger_mint(caller_id, address, value) {
    minter_to_ledger := Append(minter_to_ledger, Mint_Request(caller_id, address, value));
}

macro process_next_utxo(nutxos) {
    if(nutxos = {}) {
        return_from_update_balance();
    } else {
        with(nutxos_failing_checks \in SUBSET nutxos) {
            either {
                await(nutxos_failing_checks = nutxos);
                return_from_update_balance();
            } or {
                \* Non-deterministically pick a UTXO that passes all checks
                with(ok_utxo \in nutxos \ nutxos_failing_checks) {
                    utxos := (nutxos \ nutxos_failing_checks) \ {ok_utxo};
                    utxo := ok_utxo;
                    send_minter_to_ledger_mint(self, caller_account, utxo.value - CHECK_FEE);
                    goto Update_Balance_Mark_Minted;
                }
            }
        }
    }
}


\**********************************************************************************************
\* Model of the behavior of update balance calls.
\* Every Update_Balance process runs in an infinite loop, with each loop iteration corresponding
\* to one call of the update_balance method on the canister.
\* The cardinality of the  UPDATE_BALANCE_PROCESS_IDS set then effectively limits the number
\* of concurrent calls to update_balance
\**********************************************************************************************
process ( Update_Balance \in UPDATE_BALANCE_PROCESS_IDS)
    \* Argument of the call; start with a fixed address to reduce the state space
    variable caller_account = MINTER_CKBTC_ADDRESS,
             utxos = {};
             utxo = DUMMY_UTXO;
{
Update_Balance_Start:
    either {
        \* There are a bunch of checks that may fail in the implementation for reasons
        \* that we don't model. To align the implementation and the model, fail early
        \* non-deterministically.
        goto Update_Balance_Start;  
    } or {
        \* Non-deterministically pick a value for the argument
        with(param_address \in CK_BTC_ADDRESSES) {
            caller_account := param_address;
            await(param_address.owner \notin update_balance_locks);
            update_balance_locks := update_balance_locks \union {caller_account.owner};
            send_minter_to_btc_canister_get_utxos(self, caller_account);
        };
    };
Update_Balance_Receive_Utxos:
    with(
      response \in { r \in btc_canister_to_minter: Caller(r) = self };
    ) {
      btc_canister_to_minter := btc_canister_to_minter \ {response};
      if(VariantTag(response.response) = "GetUtxosOk") {
        with(
          received_utxos = VariantGetUnsafe("GetUtxosOk", response.response);
          \* Non-deterministically pick a subset of non-processed utxos
          \* to simulate ignoring UTXOs that are tainted or suspicious or whatever
          nutxos \in SUBSET (
            received_utxos \ (
                With_Default(utxos_state_addresses,caller_account,{})
                \union
                With_Default(finalized_utxos,caller_account.owner,{})
            )
          );
          discovered_value = Sum_Utxos(nutxos);
        ) {
          finalized_utxos := Remove_Argument(finalized_utxos,caller_account.owner);
          if(discovered_value > 0) {
            process_next_utxo(nutxos);
          } else {
            \* If nothing new has been discovered, release the lock and finish
            return_from_update_balance();
          }
        }
      } else {
        \* If the call fails, release the lock and finish
        return_from_update_balance();
      }
    };
Update_Balance_Mark_Minted:
    with(response \in { r \in ledger_to_minter: Caller(r) = self};
        ) {
        ledger_to_minter := ledger_to_minter \ {response};
        if(Is_Ok(response.status)) {
            available_utxos := available_utxos \union {utxo};
            utxos_state_addresses := caller_account:> (With_Default(utxos_state_addresses, caller_account, {}) \union {utxo} ) @@ utxos_state_addresses;
        };
    };
    process_next_utxo(utxos);
};

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "42c26389" /\ chksum(tla) = "e6415c91")
VARIABLES pc, utxos_state_addresses, available_utxos, finalized_utxos, 
          update_balance_locks, retrieve_btc_locks, locks, pending, 
          submitted_transactions, minter_to_btc_canister, 
          btc_canister_to_minter, minter_to_ledger, ledger_to_minter, 
          caller_account, utxos, utxo

vars == << pc, utxos_state_addresses, available_utxos, finalized_utxos, 
           update_balance_locks, retrieve_btc_locks, locks, pending, 
           submitted_transactions, minter_to_btc_canister, 
           btc_canister_to_minter, minter_to_ledger, ledger_to_minter, 
           caller_account, utxos, utxo >>

ProcSet == (UPDATE_BALANCE_PROCESS_IDS)

Init == (* Global variables *)
        /\ utxos_state_addresses \in Empty_Funs
        /\ available_utxos = {}
        /\ finalized_utxos \in Empty_Funs
        /\ update_balance_locks = {}
        /\ retrieve_btc_locks = {}
        /\ locks = {}
        /\ pending = <<>>
        /\ submitted_transactions = {}
        /\ minter_to_btc_canister = <<>>
        /\ btc_canister_to_minter = {}
        /\ minter_to_ledger = <<>>
        /\ ledger_to_minter = {}
        (* Process Update_Balance *)
        /\ caller_account = [self \in UPDATE_BALANCE_PROCESS_IDS |-> MINTER_CKBTC_ADDRESS]
        /\ utxos = [self \in UPDATE_BALANCE_PROCESS_IDS |-> {}]
        /\ utxo = [self \in UPDATE_BALANCE_PROCESS_IDS |-> DUMMY_UTXO]
        /\ pc = [self \in ProcSet |-> "Update_Balance_Start"]

Update_Balance_Start(self) == /\ pc[self] = "Update_Balance_Start"
                              /\ \/ /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                    /\ UNCHANGED <<update_balance_locks, minter_to_btc_canister, caller_account>>
                                 \/ /\ \E param_address \in CK_BTC_ADDRESSES:
                                         /\ caller_account' = [caller_account EXCEPT ![self] = param_address]
                                         /\ (param_address.owner \notin update_balance_locks)
                                         /\ update_balance_locks' = (update_balance_locks \union {caller_account'[self].owner})
                                         /\ minter_to_btc_canister' =                       Append(minter_to_btc_canister,
                                                                      Get_Utxos_Request(self, DEPOSIT_ADDRESS[caller_account'[self]]))
                                    /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Receive_Utxos"]
                              /\ UNCHANGED << utxos_state_addresses, 
                                              available_utxos, finalized_utxos, 
                                              retrieve_btc_locks, locks, 
                                              pending, submitted_transactions, 
                                              btc_canister_to_minter, 
                                              minter_to_ledger, 
                                              ledger_to_minter, utxos, utxo >>

Update_Balance_Receive_Utxos(self) == /\ pc[self] = "Update_Balance_Receive_Utxos"
                                      /\ \E response \in { r \in btc_canister_to_minter: Caller(r) = self }:
                                           /\ btc_canister_to_minter' = btc_canister_to_minter \ {response}
                                           /\ IF VariantTag(response.response) = "GetUtxosOk"
                                                 THEN /\ LET received_utxos == VariantGetUnsafe("GetUtxosOk", response.response) IN
                                                           \E nutxos \in            SUBSET (
                                                                           received_utxos \ (
                                                                               With_Default(utxos_state_addresses,caller_account[self],{})
                                                                               \union
                                                                               With_Default(finalized_utxos,caller_account[self].owner,{})
                                                                           )
                                                                         ):
                                                             LET discovered_value == Sum_Utxos(nutxos) IN
                                                               /\ finalized_utxos' = Remove_Argument(finalized_utxos,caller_account[self].owner)
                                                               /\ IF discovered_value > 0
                                                                     THEN /\ IF nutxos = {}
                                                                                THEN /\ update_balance_locks' = update_balance_locks \ {caller_account[self].owner}
                                                                                     /\ caller_account' = [caller_account EXCEPT ![self] = MINTER_CKBTC_ADDRESS]
                                                                                     /\ utxos' = [utxos EXCEPT ![self] = {}]
                                                                                     /\ utxo' = [utxo EXCEPT ![self] = DUMMY_UTXO]
                                                                                     /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                                                                     /\ UNCHANGED minter_to_ledger
                                                                                ELSE /\ \E nutxos_failing_checks \in SUBSET nutxos:
                                                                                          \/ /\ (nutxos_failing_checks = nutxos)
                                                                                             /\ update_balance_locks' = update_balance_locks \ {caller_account[self].owner}
                                                                                             /\ caller_account' = [caller_account EXCEPT ![self] = MINTER_CKBTC_ADDRESS]
                                                                                             /\ utxos' = [utxos EXCEPT ![self] = {}]
                                                                                             /\ utxo' = [utxo EXCEPT ![self] = DUMMY_UTXO]
                                                                                             /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                                                                             /\ UNCHANGED minter_to_ledger
                                                                                          \/ /\ \E ok_utxo \in nutxos \ nutxos_failing_checks:
                                                                                                  /\ utxos' = [utxos EXCEPT ![self] = (nutxos \ nutxos_failing_checks) \ {ok_utxo}]
                                                                                                  /\ utxo' = [utxo EXCEPT ![self] = ok_utxo]
                                                                                                  /\ minter_to_ledger' = Append(minter_to_ledger, Mint_Request(self, caller_account[self], (utxo'[self].value - CHECK_FEE)))
                                                                                                  /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Mark_Minted"]
                                                                                             /\ UNCHANGED <<update_balance_locks, caller_account>>
                                                                     ELSE /\ update_balance_locks' = update_balance_locks \ {caller_account[self].owner}
                                                                          /\ caller_account' = [caller_account EXCEPT ![self] = MINTER_CKBTC_ADDRESS]
                                                                          /\ utxos' = [utxos EXCEPT ![self] = {}]
                                                                          /\ utxo' = [utxo EXCEPT ![self] = DUMMY_UTXO]
                                                                          /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                                                          /\ UNCHANGED minter_to_ledger
                                                 ELSE /\ update_balance_locks' = update_balance_locks \ {caller_account[self].owner}
                                                      /\ caller_account' = [caller_account EXCEPT ![self] = MINTER_CKBTC_ADDRESS]
                                                      /\ utxos' = [utxos EXCEPT ![self] = {}]
                                                      /\ utxo' = [utxo EXCEPT ![self] = DUMMY_UTXO]
                                                      /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                                      /\ UNCHANGED << finalized_utxos, 
                                                                      minter_to_ledger >>
                                      /\ UNCHANGED << utxos_state_addresses, 
                                                      available_utxos, 
                                                      retrieve_btc_locks, 
                                                      locks, pending, 
                                                      submitted_transactions, 
                                                      minter_to_btc_canister, 
                                                      ledger_to_minter >>

Update_Balance_Mark_Minted(self) == /\ pc[self] = "Update_Balance_Mark_Minted"
                                    /\ \E response \in { r \in ledger_to_minter: Caller(r) = self}:
                                         /\ ledger_to_minter' = ledger_to_minter \ {response}
                                         /\ IF Is_Ok(response.status)
                                               THEN /\ available_utxos' = (available_utxos \union {utxo[self]})
                                                    /\ utxos_state_addresses' = (caller_account[self]:> (With_Default(utxos_state_addresses, caller_account[self], {}) \union {utxo[self]} ) @@ utxos_state_addresses)
                                               ELSE /\ TRUE
                                                    /\ UNCHANGED << utxos_state_addresses, 
                                                                    available_utxos >>
                                    /\ IF utxos[self] = {}
                                          THEN /\ update_balance_locks' = update_balance_locks \ {caller_account[self].owner}
                                               /\ caller_account' = [caller_account EXCEPT ![self] = MINTER_CKBTC_ADDRESS]
                                               /\ utxos' = [utxos EXCEPT ![self] = {}]
                                               /\ utxo' = [utxo EXCEPT ![self] = DUMMY_UTXO]
                                               /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                               /\ UNCHANGED minter_to_ledger
                                          ELSE /\ \E nutxos_failing_checks \in SUBSET utxos[self]:
                                                    \/ /\ (nutxos_failing_checks = utxos[self])
                                                       /\ update_balance_locks' = update_balance_locks \ {caller_account[self].owner}
                                                       /\ caller_account' = [caller_account EXCEPT ![self] = MINTER_CKBTC_ADDRESS]
                                                       /\ utxos' = [utxos EXCEPT ![self] = {}]
                                                       /\ utxo' = [utxo EXCEPT ![self] = DUMMY_UTXO]
                                                       /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                                       /\ UNCHANGED minter_to_ledger
                                                    \/ /\ \E ok_utxo \in utxos[self] \ nutxos_failing_checks:
                                                            /\ utxos' = [utxos EXCEPT ![self] = (utxos[self] \ nutxos_failing_checks) \ {ok_utxo}]
                                                            /\ utxo' = [utxo EXCEPT ![self] = ok_utxo]
                                                            /\ minter_to_ledger' = Append(minter_to_ledger, Mint_Request(self, caller_account[self], (utxo'[self].value - CHECK_FEE)))
                                                            /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Mark_Minted"]
                                                       /\ UNCHANGED <<update_balance_locks, caller_account>>
                                    /\ UNCHANGED << finalized_utxos, 
                                                    retrieve_btc_locks, locks, 
                                                    pending, 
                                                    submitted_transactions, 
                                                    minter_to_btc_canister, 
                                                    btc_canister_to_minter >>

Update_Balance(self) == Update_Balance_Start(self)
                           \/ Update_Balance_Receive_Utxos(self)
                           \/ Update_Balance_Mark_Minted(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in UPDATE_BALANCE_PROCESS_IDS: Update_Balance(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 

local_vars == << caller_account, utxos, utxo >>

Local_Init ==
    /\ caller_account = [self \in UPDATE_BALANCE_PROCESS_IDS |-> MINTER_CKBTC_ADDRESS]
    /\ utxos = [self \in UPDATE_BALANCE_PROCESS_IDS |-> {}]
    /\ utxo = [self \in UPDATE_BALANCE_PROCESS_IDS |-> DUMMY_UTXO]


====
