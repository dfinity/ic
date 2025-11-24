---- MODULE Timer ----
EXTENDS TLC, Sequences, Integers, FiniteSets, FiniteSetsExt, SequencesExt, Functions, Variants, Apalache, TLA_Hash, TypeAliases, Ckbtc_Common

CONSTANTS
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

No_Submission == Variant("NoSubmission", UNIT)
Some_Submission(submission) == Variant("SomeSubmission", submission)
Unwrap_Submission(opt_submission) ==
    VariantGetUnsafe("SomeSubmission", opt_submission)


\* These were PlusCal definitions originally, but Apalache doesn't like LAMBDAs. Turn them into
\* TLA+ definitions instead to be able to use LET/IN and give type hints.

\* @type: (Seq($withdrawalReq), $amount) => Set(Int);
possible_indexes(pndng, available_amount) == 
  LET
    \* @type: $withdrawalReq => $amount;
    amt(x) == x.amount
  IN
    {i\in 1..Len(pndng): Sum_Seq(Map(amt, SubSeq(pndng,1,i))) < available_amount}

\* @type: (Seq($withdrawalReq), Set(Int)) => Seq($withdrawalReq);
requests_to_submit(pndng, pindexes) == SubSeq(pndng,1,Cardinality(pindexes))

\* @type: Seq($withdrawalReq) => $amount;
requested_amount(reqs_to_submit) == 
  LET
    \* @type: $withdrawalReq => $amount;
    amt(y) == y.amount
  IN
    Sum_Seq(Map(amt, reqs_to_submit))
\* @type: Seq($withdrawalReq) => Seq($requestId);
submitted_request_ids(reqs_to_submit) == 
  LET
    \* @type: $withdrawalReq => $requestId;
    req_id(y) == y.request_id
  IN
    Map(req_id, reqs_to_submit)


\* @type: (Set($utxo), Seq({ owner: $btcAddress, amount: $amount })) => $submission;
New_Submission(consumed_utxos, outputs) ==
    [ consumed_utxos |-> consumed_utxos, outputs |-> outputs ]

(*--algorithm Timer {

variables
    \**********************************************************************************************
    \* BTC Network
    \**********************************************************************************************
    \* The "current state" of the BTC network, as just a set of UTXOs. Of course, this
    \* is a simplification, as the BTC network doesn't have a notion of current state.
    \* We don't attempt to define a precise mapping onto the state of the BTC network here.
    btc = { 
        [ id |-> << "GENESIS", 0 >>, owner |-> USER_BTC_ADDRESS, amount |-> BTC_SUPPLY - MINTER_INITIAL_SUPPLY], 
        [ id |-> << "GENESIS", 1 >>, owner |-> DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS], amount |-> MINTER_INITIAL_SUPPLY] };
    \**********************************************************************************************
    \* BTC Canister
    \**********************************************************************************************
    \* The state of the BTC canister, also as just a set of UTXOs. It's a
    \* snapshot of the BTC network state at some point in time.
    btc_canister = {};
    \**********************************************************************************************
    \* BTC library state (part of the minter canister state)
    \**********************************************************************************************
    \* State of the minter
    utxos_state_addresses \in Empty_Funs;
    \* Available utxos
    available_utxos = {};
    \* Finalized utxos: utxos that are being finalized but their corresponding principal is still locked
    finalized_utxos \in Empty_Funs;
    \* TODO: do we want to add this in addition to requests_sent once we figure out how garbage
    \* collection should exactly work?
    \* sent_transactions = {};
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

    \**********************************************************************************************
    \* ckBTC Ledger state
    \**********************************************************************************************
    \* The ledger is represented just through its mapping of balances
    balance \in Empty_Funs;
    \**********************************************************************************************
    \* "Buffers" used to model asynchronous communication
    \**********************************************************************************************
    \* Transaction sent from the BTC canister to the BTC network. This is not ordered,
    \* as there's no guarantee in which order the sent transactions will be applied.
    btc_canister_to_btc = {};
    \* Buffers modelling in-flight inter-canister calls. The requests are stored
    \* in sequences (i.e., ordered collections), the responses in sets (unordered).
    \* This reflects the ordering guarantees of the IC.
    minter_to_btc_canister = <<>>;
    btc_canister_to_minter = {};
    minter_to_ledger = <<>>;
    ledger_to_minter = {};
    next_request_id = 1;

macro send_minter_to_btc_canister_submit(caller_id, submission) {
    minter_to_btc_canister := Append(minter_to_btc_canister,
        Submission_Request(caller_id, submission));
}

macro reset_variables_heartbeat() {
        \* submitted := <<[request_id |-> 0, address |-> MINTER_CKBTC_ADDRESS, amount |-> 0]>>;
        submitted := <<>>;
        submitted_ids := <<>>;
        spent := {};
        outputs := <<>>;
        new_transaction := No_Submission;
}

macro send_minter_to_btc_canister_get_utxos(caller_id, address) {
    minter_to_btc_canister := Append(minter_to_btc_canister,
        Get_Utxos_Request(caller_id, DEPOSIT_ADDRESS[address]));
}


\**********************************************************************************************
\* Model of the heartbeat on the minter canister.
\* We assume that heartbeats will implement locking, such that there is only one concurrent
\* heartbeat that's not a no-op.
\* So we model the heartebat as a single process here running in an infinite loop.
\**********************************************************************************************
process (Heartbeat \in HEARTBEAT_PROCESS_IDS)
variables
        \* submitted = <<[request_id |-> 0, address |-> MINTER_CKBTC_ADDRESS, amount |-> 0]>>;
        submitted = <<>>;
        submitted_ids = <<>>;
        spent = {};
        outputs = <<>>;
        \* Use a sequence 
        new_transaction = No_Submission;
{
    Heartbeat_Start:
    while(TRUE) 
    {
        if (pending # <<>>) 
        {
            (* submit_pending_requests *)
            \* Start_Submission:
            with(available_amount = Sum_Utxos(available_utxos);
               possible_indexes_var = possible_indexes(pending, available_amount);
               requests_to_submit_var = requests_to_submit(pending, possible_indexes_var);
               requested_amount_var = requested_amount(requests_to_submit_var);
               submitted_request_ids_var = submitted_request_ids(requests_to_submit_var);
               rest_pending = SubSeq(pending,Cardinality(possible_indexes_var)+1,Len(pending));
            )
            { 
              if (requested_amount_var > 0) {
                 with(sset \in {s \in SUBSET available_utxos:
                           /\ Sum_Utxos(s) > requested_amount_var
                          /\ \A ps \in Proper_Subsets(s): Sum_Utxos(ps) <= requested_amount_var };
                          new_outputs = New_Outputs(sset, requests_to_submit_var, DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS]);
                      )
                      {
                          pending := rest_pending;
                          submitted := requests_to_submit_var;
                          submitted_ids := submitted_request_ids_var;
                          spent := sset;
                          outputs := new_outputs;
                          available_utxos := available_utxos \ spent;
                          new_transaction := Some_Submission(New_Submission(sset, new_outputs));
                          send_minter_to_btc_canister_submit(self, Unwrap_Submission(new_transaction));
                      }
              }
               else {
                  reset_variables_heartbeat();
                  goto Heartbeat_Start;
                  }
              };
        } 
        else goto Finalize_Requests;

      Conclude_Submission:
        with(response \in { r \in btc_canister_to_minter: Caller(r) = self }; change_index \in {i\in DOMAIN outputs : outputs[i].owner = DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS]}) 
        {
            btc_canister_to_minter := btc_canister_to_minter \ {response};
            if(VariantTag(response.response) = "SubmissionOk") {
                submitted_transactions := submitted_transactions \union {[requests |-> submitted_ids, txid |-> TX_HASH(Unwrap_Submission(new_transaction)), used_utxos |-> spent, change_output |-> [vout |-> change_index, vamount |-> outputs[change_index].amount]] } ;
            } else {
                \* This puts the submission at the end of the queue;
                \* this corresponds to the plans for the implementation, though for the model's purposes
                \* we could also put this anywhere
                available_utxos := available_utxos \union spent;
                pending := pending \o submitted;
                reset_variables_heartbeat();
                goto Heartbeat_Start;

            }
        };
        (* finalize_requests *)
      Finalize_Requests:
        send_minter_to_btc_canister_get_utxos(self, MINTER_CKBTC_ADDRESS);
      Receive_Change_Utxos:
        with(response \in { r \in btc_canister_to_minter: Caller(r) = self }; ) 
        {
            btc_canister_to_minter := btc_canister_to_minter \ {response};
            if( Is_Get_Utxos_Ok_Response(response) ) {
                with(utxos_from_result = Get_Utxos_Result(response);
                    new_utxos_finalize = utxos_from_result \ With_Default (utxos_state_addresses, MINTER_CKBTC_ADDRESS, {});
                    new_utxos_ids_finalize = {utxo.id : utxo \in new_utxos_finalize};
                    change_utxos_ids = {<<transaction.txid,transaction.change_output.vout>>: transaction \in submitted_transactions};
                    confirmed_transactions = {utxos[1] : utxos \in change_utxos_ids \intersect new_utxos_ids_finalize};
                    submitted_confirmed  = {tx \in submitted_transactions: tx.txid \in confirmed_transactions};
                    confirmed_utxos = UNION{transaction.used_utxos : transaction \in submitted_confirmed};
                    \* TODO: here we probably need the reverse mapping?
                    new_finalized_utxos = [ principal \in {utxo.owner : utxo \in confirmed_utxos} \intersect locks |-> { utxo \in confirmed_utxos : utxo.owner = principal} \union With_Default(finalized_utxos, principal, {})];
                    trimmed_utxos_state_addresses_except_change = [x\in {y \in DOMAIN utxos_state_addresses: utxos_state_addresses[y] \ confirmed_utxos /= {} } |-> utxos_state_addresses[x] \ confirmed_utxos];
                    trimmed_utxos_state_addresses_with_change = MINTER_CKBTC_ADDRESS :> With_Default(trimmed_utxos_state_addresses_except_change, MINTER_CKBTC_ADDRESS , {})\union new_utxos_finalize @@ trimmed_utxos_state_addresses_except_change;
                    )
                    {
                        (*
                        Record only the entries which have associated a nonempty set of utxos
                        For the minter address, we add the newly discovered
                        *)
                        utxos_state_addresses :=  trimmed_utxos_state_addresses_with_change;
                        submitted_transactions := {tx \in submitted_transactions : tx.txid \notin confirmed_transactions};
                        finalized_utxos := new_finalized_utxos @@ finalized_utxos;
                        available_utxos := available_utxos \union new_utxos_finalize;
                    };
            } else {
                reset_variables_heartbeat();
                goto Heartbeat_Start;
            }
        };
    }
}

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "bc907a55" /\ chksum(tla) = "38d1bd17")
VARIABLES pc, btc, btc_canister, utxos_state_addresses, available_utxos, 
          finalized_utxos, locks, pending, submitted_transactions, balance, 
          btc_canister_to_btc, minter_to_btc_canister, btc_canister_to_minter, 
          minter_to_ledger, ledger_to_minter, next_request_id, submitted, 
          submitted_ids, spent, outputs, new_transaction

vars == << pc, btc, btc_canister, utxos_state_addresses, available_utxos, 
           finalized_utxos, locks, pending, submitted_transactions, balance, 
           btc_canister_to_btc, minter_to_btc_canister, 
           btc_canister_to_minter, minter_to_ledger, ledger_to_minter, 
           next_request_id, submitted, submitted_ids, spent, outputs, 
           new_transaction >>

ProcSet == (HEARTBEAT_PROCESS_IDS)

Init == (* Global variables *)
        /\ btc =   {
                 [ id |-> << "GENESIS", 0 >>, owner |-> USER_BTC_ADDRESS, amount |-> BTC_SUPPLY - MINTER_INITIAL_SUPPLY],
                 [ id |-> << "GENESIS", 1 >>, owner |-> DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS], amount |-> MINTER_INITIAL_SUPPLY] }
        /\ btc_canister = {}
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
        (* Process Heartbeat *)
        /\ submitted = [self \in HEARTBEAT_PROCESS_IDS |-> <<>>]
        /\ submitted_ids = [self \in HEARTBEAT_PROCESS_IDS |-> <<>>]
        /\ spent = [self \in HEARTBEAT_PROCESS_IDS |-> {}]
        /\ outputs = [self \in HEARTBEAT_PROCESS_IDS |-> <<>>]
        /\ new_transaction = [self \in HEARTBEAT_PROCESS_IDS |-> No_Submission]
        /\ pc = [self \in ProcSet |-> "Heartbeat_Start"]

Heartbeat_Start(self) == /\ pc[self] = "Heartbeat_Start"
                         /\ IF pending # <<>>
                               THEN /\ LET available_amount == Sum_Utxos(available_utxos) IN
                                         LET possible_indexes_var == possible_indexes(pending, available_amount) IN
                                           LET requests_to_submit_var == requests_to_submit(pending, possible_indexes_var) IN
                                             LET requested_amount_var == requested_amount(requests_to_submit_var) IN
                                               LET submitted_request_ids_var == submitted_request_ids(requests_to_submit_var) IN
                                                 LET rest_pending == SubSeq(pending,Cardinality(possible_indexes_var)+1,Len(pending)) IN
                                                   IF requested_amount_var > 0
                                                      THEN /\ \E sset \in      {s \in SUBSET available_utxos:
                                                                           /\ Sum_Utxos(s) > requested_amount_var
                                                                          /\ \A ps \in Proper_Subsets(s): Sum_Utxos(ps) <= requested_amount_var }:
                                                                LET new_outputs == New_Outputs(sset, requests_to_submit_var, DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS]) IN
                                                                  /\ pending' = rest_pending
                                                                  /\ submitted' = [submitted EXCEPT ![self] = requests_to_submit_var]
                                                                  /\ submitted_ids' = [submitted_ids EXCEPT ![self] = submitted_request_ids_var]
                                                                  /\ spent' = [spent EXCEPT ![self] = sset]
                                                                  /\ outputs' = [outputs EXCEPT ![self] = new_outputs]
                                                                  /\ available_utxos' = available_utxos \ spent'[self]
                                                                  /\ new_transaction' = [new_transaction EXCEPT ![self] = Some_Submission(New_Submission(sset, new_outputs))]
                                                                  /\ minter_to_btc_canister' =                       Append(minter_to_btc_canister,
                                                                                               Submission_Request(self, (Unwrap_Submission(new_transaction'[self]))))
                                                           /\ pc' = [pc EXCEPT ![self] = "Conclude_Submission"]
                                                      ELSE /\ submitted' = [submitted EXCEPT ![self] = <<>>]
                                                           /\ submitted_ids' = [submitted_ids EXCEPT ![self] = <<>>]
                                                           /\ spent' = [spent EXCEPT ![self] = {}]
                                                           /\ outputs' = [outputs EXCEPT ![self] = <<>>]
                                                           /\ new_transaction' = [new_transaction EXCEPT ![self] = No_Submission]
                                                           /\ pc' = [pc EXCEPT ![self] = "Heartbeat_Start"]
                                                           /\ UNCHANGED << available_utxos, 
                                                                           pending, 
                                                                           minter_to_btc_canister >>
                               ELSE /\ pc' = [pc EXCEPT ![self] = "Finalize_Requests"]
                                    /\ UNCHANGED << available_utxos, pending, 
                                                    minter_to_btc_canister, 
                                                    submitted, submitted_ids, 
                                                    spent, outputs, 
                                                    new_transaction >>
                         /\ UNCHANGED << btc, btc_canister, 
                                         utxos_state_addresses, 
                                         finalized_utxos, locks, 
                                         submitted_transactions, balance, 
                                         btc_canister_to_btc, 
                                         btc_canister_to_minter, 
                                         minter_to_ledger, ledger_to_minter, 
                                         next_request_id >>

Conclude_Submission(self) == /\ pc[self] = "Conclude_Submission"
                             /\ \E response \in { r \in btc_canister_to_minter: Caller(r) = self }:
                                  \E change_index \in {i\in DOMAIN outputs[self] : outputs[self][i].owner = DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS]}:
                                    /\ btc_canister_to_minter' = btc_canister_to_minter \ {response}
                                    /\ IF VariantTag(response.response) = "SubmissionOk"
                                          THEN /\ submitted_transactions' = (submitted_transactions \union {[requests |-> submitted_ids[self], txid |-> TX_HASH(Unwrap_Submission(new_transaction[self])), used_utxos |-> spent[self], change_output |-> [vout |-> change_index, vamount |-> outputs[self][change_index].amount]] })
                                               /\ pc' = [pc EXCEPT ![self] = "Finalize_Requests"]
                                               /\ UNCHANGED << available_utxos, 
                                                               pending, 
                                                               submitted, 
                                                               submitted_ids, 
                                                               spent, outputs, 
                                                               new_transaction >>
                                          ELSE /\ available_utxos' = (available_utxos \union spent[self])
                                               /\ pending' = pending \o submitted[self]
                                               /\ submitted' = [submitted EXCEPT ![self] = <<>>]
                                               /\ submitted_ids' = [submitted_ids EXCEPT ![self] = <<>>]
                                               /\ spent' = [spent EXCEPT ![self] = {}]
                                               /\ outputs' = [outputs EXCEPT ![self] = <<>>]
                                               /\ new_transaction' = [new_transaction EXCEPT ![self] = No_Submission]
                                               /\ pc' = [pc EXCEPT ![self] = "Heartbeat_Start"]
                                               /\ UNCHANGED submitted_transactions
                             /\ UNCHANGED << btc, btc_canister, 
                                             utxos_state_addresses, 
                                             finalized_utxos, locks, balance, 
                                             btc_canister_to_btc, 
                                             minter_to_btc_canister, 
                                             minter_to_ledger, 
                                             ledger_to_minter, next_request_id >>

Finalize_Requests(self) == /\ pc[self] = "Finalize_Requests"
                           /\ minter_to_btc_canister' =                       Append(minter_to_btc_canister,
                                                        Get_Utxos_Request(self, DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS]))
                           /\ pc' = [pc EXCEPT ![self] = "Receive_Change_Utxos"]
                           /\ UNCHANGED << btc, btc_canister, 
                                           utxos_state_addresses, 
                                           available_utxos, finalized_utxos, 
                                           locks, pending, 
                                           submitted_transactions, balance, 
                                           btc_canister_to_btc, 
                                           btc_canister_to_minter, 
                                           minter_to_ledger, ledger_to_minter, 
                                           next_request_id, submitted, 
                                           submitted_ids, spent, outputs, 
                                           new_transaction >>

Receive_Change_Utxos(self) == /\ pc[self] = "Receive_Change_Utxos"
                              /\ \E response \in { r \in btc_canister_to_minter: Caller(r) = self }:
                                   /\ btc_canister_to_minter' = btc_canister_to_minter \ {response}
                                   /\ IF Is_Get_Utxos_Ok_Response(response)
                                         THEN /\ LET utxos_from_result == Get_Utxos_Result(response) IN
                                                   LET new_utxos_finalize == utxos_from_result \ With_Default (utxos_state_addresses, MINTER_CKBTC_ADDRESS, {}) IN
                                                     LET new_utxos_ids_finalize == {utxo.id : utxo \in new_utxos_finalize} IN
                                                       LET change_utxos_ids == {<<transaction.txid,transaction.change_output.vout>>: transaction \in submitted_transactions} IN
                                                         LET confirmed_transactions == {utxos[1] : utxos \in change_utxos_ids \intersect new_utxos_ids_finalize} IN
                                                           LET submitted_confirmed == {tx \in submitted_transactions: tx.txid \in confirmed_transactions} IN
                                                             LET confirmed_utxos == UNION{transaction.used_utxos : transaction \in submitted_confirmed} IN
                                                               LET new_finalized_utxos == [ principal \in {utxo.owner : utxo \in confirmed_utxos} \intersect locks |-> { utxo \in confirmed_utxos : utxo.owner = principal} \union With_Default(finalized_utxos, principal, {})] IN
                                                                 LET trimmed_utxos_state_addresses_except_change == [x\in {y \in DOMAIN utxos_state_addresses: utxos_state_addresses[y] \ confirmed_utxos /= {} } |-> utxos_state_addresses[x] \ confirmed_utxos] IN
                                                                   LET trimmed_utxos_state_addresses_with_change == MINTER_CKBTC_ADDRESS :> With_Default(trimmed_utxos_state_addresses_except_change, MINTER_CKBTC_ADDRESS , {})\union new_utxos_finalize @@ trimmed_utxos_state_addresses_except_change IN
                                                                     /\ utxos_state_addresses' = trimmed_utxos_state_addresses_with_change
                                                                     /\ submitted_transactions' = {tx \in submitted_transactions : tx.txid \notin confirmed_transactions}
                                                                     /\ finalized_utxos' = new_finalized_utxos @@ finalized_utxos
                                                                     /\ available_utxos' = (available_utxos \union new_utxos_finalize)
                                              /\ pc' = [pc EXCEPT ![self] = "Heartbeat_Start"]
                                              /\ UNCHANGED << submitted, 
                                                              submitted_ids, 
                                                              spent, outputs, 
                                                              new_transaction >>
                                         ELSE /\ submitted' = [submitted EXCEPT ![self] = <<>>]
                                              /\ submitted_ids' = [submitted_ids EXCEPT ![self] = <<>>]
                                              /\ spent' = [spent EXCEPT ![self] = {}]
                                              /\ outputs' = [outputs EXCEPT ![self] = <<>>]
                                              /\ new_transaction' = [new_transaction EXCEPT ![self] = No_Submission]
                                              /\ pc' = [pc EXCEPT ![self] = "Heartbeat_Start"]
                                              /\ UNCHANGED << utxos_state_addresses, 
                                                              available_utxos, 
                                                              finalized_utxos, 
                                                              submitted_transactions >>
                              /\ UNCHANGED << btc, btc_canister, locks, 
                                              pending, balance, 
                                              btc_canister_to_btc, 
                                              minter_to_btc_canister, 
                                              minter_to_ledger, 
                                              ledger_to_minter, 
                                              next_request_id >>

Heartbeat(self) == Heartbeat_Start(self) \/ Conclude_Submission(self)
                      \/ Finalize_Requests(self)
                      \/ Receive_Change_Utxos(self)

Next == (\E self \in HEARTBEAT_PROCESS_IDS: Heartbeat(self))

Spec == Init /\ [][Next]_vars

\* END TRANSLATION 

local_vars == << submitted, submitted_ids, spent, outputs, new_transaction >>

Local_Init ==
    /\ submitted = [self \in HEARTBEAT_PROCESS_IDS |-> <<>>]
    /\ submitted_ids = [self \in HEARTBEAT_PROCESS_IDS |-> <<>>]
    /\ spent = [self \in HEARTBEAT_PROCESS_IDS |-> {}]
    /\ outputs = [self \in HEARTBEAT_PROCESS_IDS |-> <<>>]
    /\ new_transaction = [self \in HEARTBEAT_PROCESS_IDS |-> No_Submission]


====
