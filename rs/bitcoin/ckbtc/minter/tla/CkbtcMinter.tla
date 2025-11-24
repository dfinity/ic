This is an abstract model of the main data flows in chain key Bitcoin (ckBTC): updating balance,]
retrieving Bitcoins (BTC), and resubmissions of retrieval requests.

We use PlusCal (more precisely, the C syntax thereof) to create the model. The way that the TLA tools are
set up, everything between "BEG1N TRANSLATION" and "3ND TRANSLATION" (names mangled here not to confuse the
parser) is automatically generated from the PlusCal code (which is in the "algorithm" section),
and should not be edited manually.
Note that the properties are specified after the "3ND TRANSLATION" marker.

The model makes some significant simplifying assumptions that limit its ability to find bugs:

1. While there's no precise attacker model, we roughly assume that all users collude. That is,
   we don't try to protect the funds of one ckBTC user from the other users.
2. Consequently, there's no modeling of authorization checks.
3. There is no translation between BTC and ckBTC addresses. We assume that there's a bijection
   between (1) a subset of BTC addresses and (2) all of ckBTC addresses together with a special
   "minter" address, and we simply identify the two sets.

Moreover, the analysis is done by model checking only scenarios with a finite state and
certain small bounds on parameters. In particular we bound:

1. the amount of BTC in circulation to a handful of atomic, integer currency units (i.e., a
   few Satoshi, e.g., 3 Satoshi)
2. the number of ckBTC user addresses (only a handful of those, e.g., 2 user addresses)
3. the total number of calls to retrieval minter canister methods (e.g., 2 calls to each flow).
   This is necessary to achieve finite state, as a retrieval generates a new unspent transaction
   output (UTXO), and each such UTXO requires a new identifier.
4. the total number of user-initiated transfers of BTC (e.g., 3 transfers). This is again necessary
   to make the state finite because of UTXO identifiers.
   Note that the number of ckBTC transfers (on the ckBTC ledger) is not
   bounded, as we don't store ckBTC transactions in the model.

As of 2022-08-03 and the commit:
8a8cc67c94501adc975aaae7502b5c4d6e83e82
the analysis using the TLC model checker completes without finding any invariant or liveness violations.
The execution statistics are:

15319055790 states generated, 2600578692 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 48.
The average outdegree of the complete state graph is 1 (minimum is 0, the maximum 31 and the 95th percentile is 2).
Finished in 20h 37min at (2022-07-09 10:21:40)


---- MODULE CkbtcMinter ----
EXTENDS TLC, Sequences, Integers, FiniteSets, FiniteSetsExt, SequencesExt, Functions, Variants, Apalache, TLA_Hash, TypeAliases, Ckbtc_Common


\**********************************************************************************************
(* Constants of the model *)
\**********************************************************************************************
CONSTANTS
    \**********************************************************************************************
    \* Constants determining the model size
    \**********************************************************************************************
    MAX_USER_BTC_TRANSFERS,
    \* Initial "supply" of BTC (all allocated to the user account initially)
    BTC_SUPPLY,
    \* Initial BTCs controlled by the minter; this is needed to guarantee the existence of change
    MINTER_INITIAL_SUPPLY,
    \* The set of process IDs for the update balance processes.
    \* The cardinality of the set effectively determines the number of concurrent calls
    \* to the update_balance method on the minter canister.
    UPDATE_BALANCE_PROCESS_IDS,
    \* The set of process IDs for Retrieve_BTC process.
    \* This roughly, corresponding to the set of call contexts for the retrieve_btc method,
    \* and limits the number of times that retrieve_btc can be called.
    RETRIEVE_BTC_PROCESS_IDS,
    \* Same as for retrieve_btc, just for the resubmit_retrieve_btc minter method.
    RESUBMIT_RETRIEVE_BTC_PROCESS_IDS,
    \**********************************************************************************************
    \* Other constants
    \**********************************************************************************************
    \* The "user-controlled" BTC address; we assume just one such address in this model.
    USER_BTC_ADDRESS,
    \* The ID of the PlusCal process simulating the BTC network
    BTC_PROCESS_ID,
    \* The ID of the PlusCal process simulating the ckBTC Ledger
    LEDGER_PROCESS_ID,
    \* The ID of the PlusCal process simulating the BTC canister
    BTC_CANISTER_PROCESS_ID,
    \* The ID of the PlusCal process simulating the heartbeat of the ckBTC Ledger
    HEARTBEAT_PROCESS_IDS,
    RETRIEVE_BTC_FEE,
    TX_HASH(_),
    DEPOSIT_ADDRESS


TxHash(tx) == ToString(tx)
Text_Hash(tx) == ToString(Hash(tx))

\**********************************************************************************************
\* Constants used when runing the analysis using the TLC tool
\**********************************************************************************************


Text_Deposit_Address == [ a \in CK_BTC_ADDRESSES \union {MINTER_CKBTC_ADDRESS} |-> ToString(a) ]   
Id_Deposit_Address == [ a \in CK_BTC_ADDRESSES \union {MINTER_CKBTC_ADDRESS} |-> a ]

(*
TLC has support for symmetry reduction: if a state S2 can be obtained from state
S1 by permuting values from some set, then it considers S1 and S2 to be the
same, thus decreasing the state space it has to search. For example, if we call
"update balance" on address 1, assigning a PID of 1 to this call, and then call
"update balance" on address 2, assigning a PID of 2 to this call, we know that
the effect will be the same as in the state where we permute the assignment of
the PIDs, so we can conflate the two states.

For each of the sets below, we posit that, for invariants, our model is
not sensitive to the permutations of this set. If we need to verify temporal
properties, this should be revisited, as these are tricky to get right with
symmetry reductions.
*)
Symmetry_Sets == { PRINCIPALS, SUBACCOUNTS, UPDATE_BALANCE_PROCESS_IDS, RETRIEVE_BTC_PROCESS_IDS, RESUBMIT_RETRIEVE_BTC_PROCESS_IDS }
Symmetry_Permutations == UNION { Permutations(S) : S \in Symmetry_Sets }


\**********************************************************************************************
\* Auxiliary definitions
\**********************************************************************************************

\* Compute the new outputs needed to transfer the BTCs to an array of destinations

VARIABLES
    btc,
    btc_canister,
    utxos_state_addresses,
    locks,
    balance,
    btc_canister_to_btc,
    minter_to_btc_canister,
    btc_canister_to_minter,
    minter_to_ledger,
    ledger_to_minter,
    next_request_id,
    pc,
    submitted,
    submitted_ids,
    spent,
    outputs,
    nr_user_transfers,
    amount,
    caller_account,
    new_utxos,
    new_transaction,
    pending,
    finalized_utxos,
    available_utxos,
    submitted_transactions

vars == <<
    btc,
    btc_canister,
    utxos_state_addresses,
    locks,
    balance,
    btc_canister_to_btc,
    minter_to_btc_canister,
    btc_canister_to_minter,
    minter_to_ledger,
    ledger_to_minter,
    next_request_id,
    pc,
    submitted,
    submitted_ids,
    spent,
    outputs,
    nr_user_transfers,
    amount,
    caller_account,
    new_utxos,
    new_transaction,
    pending,
    finalized_utxos,
    available_utxos,
    submitted_transactions
    >>


Retrieve_BTC == INSTANCE Retrieve_BTC
Update_Balance == INSTANCE Update_Balance
Timer == INSTANCE Timer
Environment == INSTANCE Environment

\**********************************************************************************************
\* Model sanity checks
\**********************************************************************************************
\* A bunch of properties we expect to be violated, as not violating them would mean
\* that our model can't do something we expect it to be able to do

Sanity_Inv_Cant_Deposit_To_Ck_BTC ==
    Utxos_Owned_By(btc, Image(DEPOSIT_ADDRESS, CK_BTC_ADDRESSES)) = {}

Sanity_Inv_Cant_Mint_Ck_BTC == \A addr \in CK_BTC_ADDRESSES \intersect DOMAIN balance:
    balance[addr] = 0

Sanity_Inv_Cant_Mint_To_Two_Addresses == ~(\E a1, a2 \in CK_BTC_ADDRESSES:
    /\ a1 # a2
    /\ a1 \in DOMAIN balance
    /\ balance[a1] # 0
    /\ a2 \in DOMAIN balance
    /\ balance[a2] # 0
    )

\* Sanity_Inv_Cant_Update_Two_Different_Addresses == \A p1, p2 \in UPDATE_BALANCE_PROCESS_IDS:
\*     /\ pc[p1] = "Done"
\*     /\ pc[p2] = "Done"
\*     =>
\*       caller_account[p1] = caller_account[p2]

\* Sanity_Inv_Cant_Have_Two_Deposits_To_Ck_BTC ==
\*     Cardinality(DOMAIN Utxos_Owned_By(btc, Image(DEPOSIT_ADDRESS, CK_BTC_ADDRESSES))) <= 1

Sanity_Inv_Cant_Deposit_To_Two_Ck_BTC_Addresses == ~(
    \E a1, a2 \in CK_BTC_ADDRESSES:
        /\ a1 # a2
        /\ Utxos_Owned_By(btc, {DEPOSIT_ADDRESS[a1]}) # {}
        /\ Utxos_Owned_By(btc, {DEPOSIT_ADDRESS[a2]}) # {}
)
Sanity_Inv_At_Most_One_Utxo == Cardinality(btc) <= 1

Sanity_Inv_Just_One_Message_To_Ledger == Len(minter_to_ledger) <= 1
Sanity_Inv_Just_One_Message_To_BTC_Canister == Len(minter_to_btc_canister) <= 1
Sanity_Inv_Just_One_Response_From_BTC_Canister == Cardinality(btc_canister_to_minter) <= 1

BTC_Balance_Of(addresses) == Sum_Utxos(Utxos_Owned_By(btc, addresses))

Sanity_No_Simultaneous_Minter_And_User_Owned_BTC ==
    BTC_Balance_Of({DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS]}) # 0 <=> BTC_Balance_Of({USER_BTC_ADDRESS}) = 0

\* TODO: For some reason this is not falsified, even though I can find a counterexample
\* using the TLA graph explorer?
Sanity_User_Stays_At_0 ==  LET
    user_btc_balance == BTC_Balance_Of({USER_BTC_ADDRESS})
  IN
    user_btc_balance = 0 => [](user_btc_balance = 0)

\**********************************************************************************************
\* Invariants
\**********************************************************************************************
\* Some desired invariants of the system.

\* The main invariant: the sum of balances on the CkBTC ledger never exceeds the sum of UTXOs
\* controlled by minter addresses

Inv_No_Unbacked_Ck_BTC ==
    Sum_F(LAMBDA x: balance[x], DOMAIN balance) <= BTC_Balance_Of(Image(DEPOSIT_ADDRESS, CK_BTC_ADDRESSES \union {MINTER_CKBTC_ADDRESS}))

\* TODO: this is a newly added invariant, it hasn't been model checked yet
\* Any UTXOs that are deemed as available should at all times currently exist on the BTC network
Inv_Available_Exist_On_The_BTC_Network ==
    available_utxos \subseteq btc

\* We don't want to have any locked addresses once all update processes are done
Inv_No_Locks_When_Done ==
    /\ \A p \in UPDATE_BALANCE_PROCESS_IDS: pc[p] = "Done"
   =>
    locks = {}

\* This is an invariant to check that the model itself doesn't create any new BTC (the BTC supply stays constant)
Inv_BTC_Supply_Constant ==
    Sum_Utxos(btc) = BTC_SUPPLY

\* An invariant to check that the model correctly assigns fresh IDs to different UTXOs
Inv_Distinct_Utxo_Ids == \A utxo1, utxo2 \in btc: utxo1.id = utxo2.id => utxo1 = utxo2


\**********************************************************************************************
\* Liveness
\**********************************************************************************************

\* The main liveness property: eventually, the supply of ckBTC will equal the sum of the
\* UTXOs on minter-controlled Bitcoin addresses. This is assuming "quiescence". In particular,
\* it assumes that the users don't infinitely often transfer BTC to a minter-controlled address,
\* and don't start BTC retrievals infinitely often. This assumption is true in the model, as
\* the BTC transfers are capped by MAX_USER_BTC_TRANSFERS, and the number of retrievals is capped
\* by the cardinality of RETRIEVE_BTC_PROCESS_IDS.
\*
\* Moreover, this property can only be fulfilled under a few fairness conditions. For example,
\* it won't hold if the BTC canister just keeps refusing all requests from the minter.
\* These conditions will be defined in a separate fairness constraint.
\*
\* Finally, this property also falls apart if external users just transfer their BTC to the
\* minter's change address (or retrieve it ). We will also ignore such scenarios in the analysis,
\* and disallow them in a separate constraint.
\*
No_BTC_Left_Behind ==
    []<>(Sum_F(LAMBDA x: balance[x], DOMAIN balance) = 
        (BTC_Balance_Of(Image(DEPOSIT_ADDRESS, CK_BTC_ADDRESSES \union {MINTER_CKBTC_ADDRESS}))) - MINTER_INITIAL_SUPPLY)

Fairness_Condition ==
    \* Fairness of the BTC canister processing minter submission request without giving out errors.
    \* Note that we require strong fairness here; if the BTC canister sends out an error
    \* response, this disables (or can disable) the BTC canister transition temporarily,
    \* which means it's not continuously enabled (as required for weak fairness).
    \* Also, we need a separate condition for each "interesting" type of message. E.g.,
    \* it's not enough if the BTC canister responds to a get_utxos request without giving an error,
    \* but chooses to fail all submission requests, or if it keeps failing get_utxos requests
    \* for a particular address
    /\ SF_vars(
        /\ Environment!BTC
        /\ minter_to_btc_canister # <<>>
        /\ minter_to_btc_canister' # minter_to_btc_canister
        /\ Is_Submission_Request(Head(minter_to_btc_canister))
        /\ LET req_pid == Caller(Head(minter_to_btc_canister)) IN
                \A resp \in btc_canister_to_minter': Caller(resp) = req_pid => VariantTag(resp.response) = "SubmissionOk"
       )
    /\ \A addr \in CK_BTC_ADDRESSES \union {MINTER_CKBTC_ADDRESS}: SF_vars(
        /\ Environment!BTC_Canister
        /\ minter_to_btc_canister # <<>>
        /\ minter_to_btc_canister' # minter_to_btc_canister
        /\ Is_Get_Utxos_Request(Head(minter_to_btc_canister))
        /\ Get_Utxos_Request_Address(Head(minter_to_btc_canister)) = DEPOSIT_ADDRESS[addr]
        /\ LET req_pid == Caller(Head(minter_to_btc_canister)) IN
                \A resp \in btc_canister_to_minter': Caller(resp) = req_pid => VariantTag(resp.response) = "GetUtxosOk"
       )
    \* Fairness of the ledger responding to the minter. Because of the same reasons as for the
    \* BTC canister, we ask for strong fairness here. However, the ledger can also legitimately
    \* return errors (e.g., because it's been asked to burn something that doesn't exist). Thus,
    \* we add a flag to track whether errors are "spontaneous" or not, and only require
    /\ SF_vars(
        /\ Environment!Ledger
        /\ minter_to_ledger # <<>>
        /\ minter_to_ledger' # minter_to_ledger
        /\ {} = { r \in ledger_to_minter' :
            /\ Caller(r) = Caller(Head(minter_to_ledger))
            /\ Is_System_Err(Status(r)) }
        )
    \* Fairness of the BTC network processing the BTC canister messages. Weak fairness is
    \* enough here, as BTC network doesn't return errors.
    /\ WF_vars(Environment!BTC /\ btc_canister_to_btc # {} /\ btc_canister_to_btc' # btc_canister_to_btc)
    \* We also want the BTC canister to not postpone refreshing its view of BTC network forever
    /\ WF_vars(
        /\ Environment!BTC
        /\ btc_canister # btc
        /\ btc_canister' = btc
       )
    \* Fairness of balance updates: for each address addr, we will start Update_Balance
    \* infinitely often with that address chosen as the argument. We use strong fairness as
    \* a step that chooses a different addr' may (temporarily) disable Update_Balance
    /\ \A addr \in CK_BTC_ADDRESSES: SF_vars(\E pid \in UPDATE_BALANCE_PROCESS_IDS:
            /\ Update_Balance!Update_Balance(pid)
            /\ pc[pid] = "Update_Balance_Start"
            /\ caller_account'[pid] = addr
        )
    \* Additionally, we want weak fairness for the remaining Update_Balance steps (they
    \* can't be ignored forever if they are enabled)

    /\ \A pid \in UPDATE_BALANCE_PROCESS_IDS: WF_vars(Update_Balance!Update_Balance(pid))
    /\ \A pid \in RETRIEVE_BTC_PROCESS_IDS: WF_vars(Retrieve_BTC!Retrieve_BTC(pid))
    (* /\ \A pid \in RESUBMIT_RETRIEVE_BTC_PROCESS_IDS: WF_vars(Resubmit_Retrieve_BTC(pid)) *)
    /\ \A pid \in HEARTBEAT_PROCESS_IDS: WF_vars(Timer!Heartbeat(pid))

 \* To achieve the equality between ckBTC supply and the sum of UTXOs under the minter's control,
\* we have to assume that the users don't just transfer money to the ckBTC change address.
Prevent_External_Transfers_To_Change_Address ==
    \* Either this was not a user-initiated BTC transfer (because all of the previously
    \* user-owned UTXOs are intact)...
    \/ Utxos_Owned_By(btc, {USER_BTC_ADDRESS}) \subseteq Utxos_Owned_By(btc', {USER_BTC_ADDRESS})
    \* ...or no new UTXOs were added to the change address
    \/ Utxos_Owned_By(btc', {DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS]}) \subseteq Utxos_Owned_By(btc, {DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS]})

Prevent_Retrievals_To_Change_Address ==
    \* The pid constraints determine the moment when the model decides on the destination of
    \* a BTC retrieval...
    \A pid \in RETRIEVE_BTC_PROCESS_IDS:
            /\ pc[pid] = "Retrieve_BTC_Wait_Burn"
            /\ pc'[pid] = "Done"
            /\ pending' # pending
        =>
            \* ...and we require that the destination is not the change address
            Head(pending').address # DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS]

 Prevent_Donations_To_Change_Address ==
    /\ Prevent_External_Transfers_To_Change_Address
    /\ Prevent_Retrievals_To_Change_Address

ProcSet == {BTC_PROCESS_ID} \cup {BTC_CANISTER_PROCESS_ID} \cup {LEDGER_PROCESS_ID} \cup (UPDATE_BALANCE_PROCESS_IDS) \cup (RETRIEVE_BTC_PROCESS_IDS) \cup (HEARTBEAT_PROCESS_IDS)

Init == (* Global variables *)
    /\ Update_Balance!Local_Init
    /\ Retrieve_BTC!Local_Init
    /\ Timer!Local_Init
    /\ Environment!Local_Init
    /\ utxos_state_addresses \in Empty_Funs
    /\ available_utxos = {}
    /\ finalized_utxos \in Empty_Funs
    /\ locks = {}
    /\ pending = <<>>
    /\ submitted_transactions = {}
    /\ balance \in Empty_Funs
    /\ btc_canister_to_btc = {}
    /\ minter_to_btc_canister = <<>>
    /\ btc_canister_to_minter = {}
    /\ minter_to_ledger = <<>>
    /\ ledger_to_minter = {}
    /\ next_request_id = 1
    /\ pc = [self \in ProcSet |-> CASE self = BTC_PROCESS_ID -> "BTC"
                                        [] self = BTC_CANISTER_PROCESS_ID -> "BTC_Canister"
                                        [] self = LEDGER_PROCESS_ID -> "Ledger"
                                        [] self \in UPDATE_BALANCE_PROCESS_IDS -> "Update_Balance_Start"
                                        [] self \in RETRIEVE_BTC_PROCESS_IDS -> "Retrieve_BTC_Start"
                                        [] self \in HEARTBEAT_PROCESS_IDS -> "Heartbeat_Start"]

retrieve_btc_local_vars == << amount, next_request_id >>
timer_local_vars == << submitted, submitted_ids, spent, outputs, new_transaction >>
environment_local_vars == << btc, btc_canister, balance, nr_user_transfers, btc_canister_to_btc >>
update_balance_local_vars == << caller_account, new_utxos >>
minter_global_vars == << utxos_state_addresses, locks, 
                        pending, finalized_utxos,
                        available_utxos, submitted_transactions >>


Next == 
    \/ \E pid \in UPDATE_BALANCE_PROCESS_IDS:
        /\ Update_Balance!Update_Balance(pid) 
        /\ UNCHANGED retrieve_btc_local_vars
        /\ UNCHANGED timer_local_vars
        /\ UNCHANGED environment_local_vars
    \/ \E pid \in RETRIEVE_BTC_PROCESS_IDS:
        /\ Retrieve_BTC!Retrieve_BTC(pid)
        /\ UNCHANGED update_balance_local_vars
        /\ UNCHANGED timer_local_vars
        /\ UNCHANGED environment_local_vars
    \/ \E pid \in HEARTBEAT_PROCESS_IDS:
        /\ Timer!Heartbeat(pid)
        /\ UNCHANGED update_balance_local_vars
        /\ UNCHANGED retrieve_btc_local_vars
        /\ UNCHANGED environment_local_vars
    \/ 
        /\ Environment!Next
        /\ UNCHANGED update_balance_local_vars
        /\ UNCHANGED retrieve_btc_local_vars
        /\ UNCHANGED timer_local_vars
        /\ UNCHANGED minter_global_vars
        /\ UNCHANGED pc

Liveness_Spec ==
    /\ Init
    /\ [][Next /\ Prevent_Donations_To_Change_Address]_vars
    /\ Fairness_Condition

====
