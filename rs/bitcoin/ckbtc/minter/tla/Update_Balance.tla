---- MODULE Update_Balance ----
EXTENDS TLC, Sequences, Integers, FiniteSets, FiniteSetsExt, SequencesExt, Functions, Variants, Apalache, TLA_Hash, TypeAliases, Ckbtc_Common

CONSTANTS
    \* The set of process IDs for the update balance processes.
    \* The cardinality of the set effectively determines the number of concurrent calls
    \* to the update_balance method on the minter canister.
    UPDATE_BALANCE_PROCESS_IDS,
    DEPOSIT_ADDRESS

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
            locks := locks \ {caller_account.owner};
            caller_account := MINTER_CKBTC_ADDRESS;
            new_utxos := {};
            goto Update_Balance_Start;
}

macro send_minter_to_btc_canister_get_utxos(caller_id, address) {
    minter_to_btc_canister := Append(minter_to_btc_canister,
        Get_Utxos_Request(caller_id, DEPOSIT_ADDRESS[address]));
}

\* A set of small auxiliary macros used for inter-canister calls
macro send_minter_to_ledger_mint(caller_id, address, amount) {
    minter_to_ledger := Append(minter_to_ledger, Mint_Request(caller_id, address, amount));
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
             new_utxos = {};

{
Update_Balance_Start:
    \* Non-deterministically pick a value for the argument
    with(param_address \in CK_BTC_ADDRESSES) {
        caller_account := param_address;
        await(param_address.owner \notin locks);
        locks := locks \union {caller_account.owner};
        send_minter_to_btc_canister_get_utxos(self, caller_account);
    };
Update_Balance_Receive_Utxos:
    with(
      response \in { r \in btc_canister_to_minter: Caller(r) = self };
    ) {
      btc_canister_to_minter := btc_canister_to_minter \ {response};
      if(VariantTag(response.response) = "GetUtxosOk") {
        with(
          utxos = VariantGetUnsafe("GetUtxosOk", response.response);
          nutxos = utxos \ (
            With_Default(utxos_state_addresses,caller_account,{})
            \union
            With_Default(finalized_utxos,caller_account.owner,{})
          );
          discovered_amount = Sum_Utxos(nutxos);
        ) {
          finalized_utxos := Remove_Argument(finalized_utxos,caller_account.owner);
          if(discovered_amount > 0) {
            send_minter_to_ledger_mint(self, caller_account, discovered_amount);
            new_utxos := nutxos;
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
            available_utxos := available_utxos \union new_utxos;
            utxos_state_addresses := caller_account:> (With_Default(utxos_state_addresses, caller_account, {}) \union new_utxos ) @@ utxos_state_addresses;
        };
    };
    \* Regardless of whether the call to the minter succeeds, release the lock
    return_from_update_balance();
};

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "51022f71" /\ chksum(tla) = "57d262e0")
VARIABLES pc, utxos_state_addresses, available_utxos, finalized_utxos, locks, 
          pending, submitted_transactions, minter_to_btc_canister, 
          btc_canister_to_minter, minter_to_ledger, ledger_to_minter, 
          caller_account, new_utxos

vars == << pc, utxos_state_addresses, available_utxos, finalized_utxos, locks, 
           pending, submitted_transactions, minter_to_btc_canister, 
           btc_canister_to_minter, minter_to_ledger, ledger_to_minter, 
           caller_account, new_utxos >>

ProcSet == (UPDATE_BALANCE_PROCESS_IDS)

Init == (* Global variables *)
        /\ utxos_state_addresses \in Empty_Funs
        /\ available_utxos = {}
        /\ finalized_utxos \in Empty_Funs
        /\ locks = {}
        /\ pending = <<>>
        /\ submitted_transactions = {}
        /\ minter_to_btc_canister = <<>>
        /\ btc_canister_to_minter = {}
        /\ minter_to_ledger = <<>>
        /\ ledger_to_minter = {}
        (* Process Update_Balance *)
        /\ caller_account = [self \in UPDATE_BALANCE_PROCESS_IDS |-> MINTER_CKBTC_ADDRESS]
        /\ new_utxos = [self \in UPDATE_BALANCE_PROCESS_IDS |-> {}]
        /\ pc = [self \in ProcSet |-> "Update_Balance_Start"]

Update_Balance_Start(self) == /\ pc[self] = "Update_Balance_Start"
                              /\ \E param_address \in CK_BTC_ADDRESSES:
                                   /\ caller_account' = [caller_account EXCEPT ![self] = param_address]
                                   /\ (param_address.owner \notin locks)
                                   /\ locks' = (locks \union {caller_account'[self].owner})
                                   /\ minter_to_btc_canister' =                       Append(minter_to_btc_canister,
                                                                Get_Utxos_Request(self, DEPOSIT_ADDRESS[caller_account'[self]]))
                              /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Receive_Utxos"]
                              /\ UNCHANGED << utxos_state_addresses, 
                                              available_utxos, finalized_utxos, 
                                              pending, submitted_transactions, 
                                              btc_canister_to_minter, 
                                              minter_to_ledger, 
                                              ledger_to_minter, new_utxos >>

Update_Balance_Receive_Utxos(self) == /\ pc[self] = "Update_Balance_Receive_Utxos"
                                      /\ \E response \in { r \in btc_canister_to_minter: Caller(r) = self }:
                                           /\ btc_canister_to_minter' = btc_canister_to_minter \ {response}
                                           /\ IF VariantTag(response.response) = "GetUtxosOk"
                                                 THEN /\ LET utxos == VariantGetUnsafe("GetUtxosOk", response.response) IN
                                                           LET nutxos ==          utxos \ (
                                                                           With_Default(utxos_state_addresses,caller_account[self],{})
                                                                           \union
                                                                           With_Default(finalized_utxos,caller_account[self].owner,{})
                                                                         ) IN
                                                             LET discovered_amount == Sum_Utxos(nutxos) IN
                                                               /\ finalized_utxos' = Remove_Argument(finalized_utxos,caller_account[self].owner)
                                                               /\ IF discovered_amount > 0
                                                                     THEN /\ minter_to_ledger' = Append(minter_to_ledger, Mint_Request(self, caller_account[self], discovered_amount))
                                                                          /\ new_utxos' = [new_utxos EXCEPT ![self] = nutxos]
                                                                          /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Mark_Minted"]
                                                                          /\ UNCHANGED << locks, 
                                                                                          caller_account >>
                                                                     ELSE /\ locks' = locks \ {caller_account[self].owner}
                                                                          /\ caller_account' = [caller_account EXCEPT ![self] = MINTER_CKBTC_ADDRESS]
                                                                          /\ new_utxos' = [new_utxos EXCEPT ![self] = {}]
                                                                          /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                                                          /\ UNCHANGED minter_to_ledger
                                                 ELSE /\ locks' = locks \ {caller_account[self].owner}
                                                      /\ caller_account' = [caller_account EXCEPT ![self] = MINTER_CKBTC_ADDRESS]
                                                      /\ new_utxos' = [new_utxos EXCEPT ![self] = {}]
                                                      /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                                      /\ UNCHANGED << finalized_utxos, 
                                                                      minter_to_ledger >>
                                      /\ UNCHANGED << utxos_state_addresses, 
                                                      available_utxos, pending, 
                                                      submitted_transactions, 
                                                      minter_to_btc_canister, 
                                                      ledger_to_minter >>

Update_Balance_Mark_Minted(self) == /\ pc[self] = "Update_Balance_Mark_Minted"
                                    /\ \E response \in { r \in ledger_to_minter: Caller(r) = self}:
                                         /\ ledger_to_minter' = ledger_to_minter \ {response}
                                         /\ IF Is_Ok(response.status)
                                               THEN /\ available_utxos' = (available_utxos \union new_utxos[self])
                                                    /\ utxos_state_addresses' = (caller_account[self]:> (With_Default(utxos_state_addresses, caller_account[self], {}) \union new_utxos[self] ) @@ utxos_state_addresses)
                                               ELSE /\ TRUE
                                                    /\ UNCHANGED << utxos_state_addresses, 
                                                                    available_utxos >>
                                    /\ locks' = locks \ {caller_account[self].owner}
                                    /\ caller_account' = [caller_account EXCEPT ![self] = MINTER_CKBTC_ADDRESS]
                                    /\ new_utxos' = [new_utxos EXCEPT ![self] = {}]
                                    /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                    /\ UNCHANGED << finalized_utxos, pending, 
                                                    submitted_transactions, 
                                                    minter_to_btc_canister, 
                                                    btc_canister_to_minter, 
                                                    minter_to_ledger >>

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

local_vars == << caller_account, new_utxos >>

Local_Init ==
    /\ caller_account = [self \in UPDATE_BALANCE_PROCESS_IDS |-> MINTER_CKBTC_ADDRESS]
    /\ new_utxos = [self \in UPDATE_BALANCE_PROCESS_IDS |-> {}]


====
