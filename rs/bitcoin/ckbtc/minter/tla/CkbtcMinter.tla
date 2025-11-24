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
EXTENDS TLC, Sequences, Integers, FiniteSets, FiniteSetsExt, SequencesExt, Functions, Variants, Apalache, TLA_Hash, TypeAliases

\**********************************************************************************************
(* Some general auxiliary definitions on sets, functions etc. *)
\**********************************************************************************************

Proper_Subsets(S) == SUBSET S \ {S}

\* @type: (a => Int, Set(a)) => Int;
Sum_F(f(_), S) == FoldSet(LAMBDA x, y: f(x) + y, 0, S)

\* @type: (a -> b, a, b) => b;
With_Default(f, x, default) == IF x \in DOMAIN f THEN f[x] ELSE default

\* @type: (a -> b, Set(a)) => (a -> b);
Remove_Arguments(f, S) == [ x \in (DOMAIN f \ S) |-> f[x] ]
\* @type: (a -> b, a) => (a -> b);
Remove_Argument(f, x) == Remove_Arguments(f, {x})

\* @type: (a -> b, Set(a)) => Set(b);
Image(f, S) == { f[x] : x \in S }

\* @type: Set(a -> b);
Empty_Funs == [ {} -> {} ]


\**********************************************************************************************
(* Constants of the model *)
\**********************************************************************************************
CONSTANTS
    \**********************************************************************************************
    \* Constants determining the model size
    \**********************************************************************************************
    \* Principals that hold ckBTC
    PRINCIPALS,
    \* Subaccounts for the ck_btc_addresses
    SUBACCOUNTS,
    \* Every BTC transfer allocates a new UTXO id. Allowing an infinite number of transfers
    \* would thus require infinite state. So we bound the number of BTC transfers a user is
    \* allowed to make.
    \* Minter principal
    MINTER_PRINCIPAL,
    \* Minter change subaccount
    MINTER_SUBACCOUNT,
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

\* The version of BURN_ADDRESS used with TLC for analysis, as TLC doesn't care about types
\* @type: $principal => $ckbtcAddress;
BURN_ADDRESS(p) == [owner |-> MINTER_PRINCIPAL, subaccount |-> p]

MINTER_CKBTC_ADDRESS == [owner |-> MINTER_PRINCIPAL, subaccount |-> MINTER_SUBACCOUNT]

\* CK_BTC addresses
CK_BTC_ADDRESSES == [owner:PRINCIPALS, subaccount: SUBACCOUNTS]

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


\* @type: (a => b, Seq(a)) => Seq(b);
Map(f(_), seq) == FoldRight(LAMBDA x, y: <<f(x)>> \o y, seq, <<>>)

\* @type: Seq(Int) => Int;
Sum_Seq(seq) == FoldRight(LAMBDA x, y: x + y, seq, 0)

\* Definitions on UTXO sets
\* @type: (Int, $utxo) => Int;
Add_Utxo_Amount(amt, utxo) == utxo.amount + amt
\* @type: Set($utxo) => $amount;
Sum_Utxos(S) == \* Sum_F(LAMBDA x: x.amount, S)
                ApaFoldSet(Add_Utxo_Amount, 0, S)
\* @type: (Set({owner: $btcAddress, b}), Set($btcAddress)) => Set({owner: $btcAddress, b});
Utxos_Owned_By(utxos, S) == { utxo \in utxos: utxo.owner \in S }


\* "Standard" inter-canister message definitions, used for communication between any pair of canisters.
\* E.g., whether a response is an error or not, what the PID of the caller of a request is, etc.
Status_Ok == Variant("OK", UNIT)
Status_Err == Variant("Err", UNIT)
Status_System_Err == Variant("SystemErr", UNIT)
Is_Ok(status) == VariantTag(status) = "OK"
Is_System_Err(status) == VariantTag(status) = "SystemErr"

\* @type: { caller_id: $pid, b } => $pid;
Caller(msg) == msg.caller_id
\* @type: { status: $ledgerToMinterResponseType, b } => $ledgerToMinterResponseType;
Status(msg) == msg.status

\* Auxiliary definitions for specific kinds of messages (e.g., a get_utxos request)
\* @type: ($pid, $btcAddress) => $minterToBtcCanisterRequest;
Get_Utxos_Request(caller_id, btc_address) == [
    caller_id |-> caller_id,
    request |-> Variant("GetUtxos", btc_address)
]
\* @type: $minterToBtcCanisterRequest => Bool;
Is_Get_Utxos_Request(req) == VariantTag(req.request) = "GetUtxos"
\* @type: $minterToBtcCanisterRequest => $btcAddress;
Get_Utxos_Request_Address(req) == VariantGetUnsafe("GetUtxos", req.request)

\* @type: ($pid, Set($utxo)) => $btcCanisterToMinterResponse;
Get_Utxos_Response(caller_id, utxos) == [ caller_id |-> caller_id, response |-> Variant("GetUtxosOk", utxos) ]
\* @type: $btcCanisterToMinterResponse => Bool;
Is_Get_Utxos_Ok_Response(resp) == VariantTag(resp.response) = "GetUtxosOk"

\* @type: $btcCanisterToMinterResponse => Set($utxo);
Get_Utxos_Result(resp) == VariantGetUnsafe("GetUtxosOk", resp.response)

\* @type: (Set($utxo), Seq({ owner: $btcAddress, amount: $amount })) => $submission;
New_Submission(consumed_utxos, outputs) ==
    [ consumed_utxos |-> consumed_utxos, outputs |-> outputs ]

Submission_Request(caller_id, submission) == [
    caller_id |-> caller_id,
    request |-> Variant("Submission", submission)
]
\* @type: $minterToBtcCanisterRequest => Bool;
Is_Submission_Request(req) == VariantTag(req.request) = "Submission"

Mint_Request(caller_id, to_address, amount) == [
    request |-> Variant("Mint", [ to |-> to_address, amount |-> amount ]),
    caller_id |-> caller_id
]
\* @type: $minterToLedgerRequest => Bool;
Is_Mint_Request(req) == VariantTag(req.request) = "Mint"

Burn_Request(caller_id, address, amount) == [
    request |-> Variant("Burn", [ address |-> address, amount |-> amount ]),
    caller_id |-> caller_id
]
\* @type: $minterToLedgerRequest => Bool;
Is_Burn_Request(req) == VariantTag(req.request) = "Burn"

\* Other auxiliary definitions

\* Put a submission at the end of the minter's "pending" queue
\* @type: (Seq($withdrawalReq), $requestId, $btcAddress, $amount) => Seq($withdrawalReq);
Queue_Pending(pending, request_id, address, amount) == Append(pending,
    [ request_id |-> request_id, address |-> address, amount |-> amount ])

\* Compute the new outputs needed to transfer the BTCs to an array of destinations

\* @type: (Set($utxo), Seq({ address: $btcAddress, amount: $amount, b }), $btcAddress) => Seq({ owner: $btcAddress, amount: $amount });
New_Outputs(utxos, requests, change_address) ==
    LET
        total_available == Sum_Utxos(utxos)
        \* Apalache doesn't seem to like lambdas, so introduce a definition
        \* @type: { address: $btcAddress, amount: $amount } => $amount;
        get_amt(request) == request.amount
        total_requested == Sum_Seq(Map(get_amt, requests))
        change == total_available - total_requested
        parent_ids == { utxo.id : utxo \in utxos }
        \* @type: { address: $btcAddress, amount: $amount } => { owner: $btcAddress, amount: $amount };
        mk_record(request) == [ owner |-> request.address, amount |-> request.amount ]
        new_outputs == Map(mk_record, requests)
    IN
        new_outputs \o
        IF change > 0 THEN << [ owner |-> change_address, amount |-> change ] >> ELSE << >>


\* @type: $submission => Set($utxo);
Utxos_Of(submission) ==
    LET
        tx_hash == TX_HASH(submission)
    IN
        { [id |-> << tx_hash, i >>, owner |-> submission.outputs[i].owner, amount |-> submission.outputs[i].amount] 
            : i \in 1..Len(submission.outputs) }


No_Submission == Variant("NoSubmission", UNIT)
Some_Submission(submission) == Variant("SomeSubmission", submission)
Unwrap_Submission(opt_submission) ==
    VariantGetUnsafe("SomeSubmission", opt_submission)

\* Remove a key from the balance map (i.e., undefine the partial function for that key) if its value is 0.
Remove_Balance_If_Zero(addr, b) == IF addr \in DOMAIN b /\ b[addr] = 0 THEN Remove_Argument(b, addr) ELSE b

BTC_Canister_Error_Response(caller_id) == [ caller_id |-> caller_id, response |-> Variant("Error", UNIT) ]

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


\**********************************************************************************************
\* The start of the PlusCal definitions
\**********************************************************************************************
(* --algorithm ck_btc {

\**********************************************************************************************
\* The model state
\**********************************************************************************************
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
    resubmit_count = 1;

\* A set of small auxiliary macros used for inter-canister calls
macro send_minter_to_ledger_mint(caller_id, address, amount) {
    minter_to_ledger := Append(minter_to_ledger, Mint_Request(caller_id, address, amount));
}

macro send_minter_to_ledger_burn(caller_id, address, amount) {
    minter_to_ledger := Append(minter_to_ledger, Burn_Request(caller_id, address, amount));
}

macro respond_ledger_to_minter(caller_id, status) {
    ledger_to_minter := ledger_to_minter \union { [ caller_id |-> caller_id, status |-> status ] }
}

macro send_minter_to_btc_canister_get_utxos(caller_id, address) {
    minter_to_btc_canister := Append(minter_to_btc_canister,
        Get_Utxos_Request(caller_id, DEPOSIT_ADDRESS[address]));
}

macro send_minter_to_btc_canister_submit(caller_id, submission) {
    minter_to_btc_canister := Append(minter_to_btc_canister,
        Submission_Request(caller_id, submission));
}

macro respond_btc_canister_to_minter_utxos(caller_id, utxos) {
    btc_canister_to_minter := btc_canister_to_minter \union { Get_Utxos_Response(caller_id, utxos) };
}

macro respond_btc_canister_to_minter_submission_ok(caller_id) {
    btc_canister_to_minter := btc_canister_to_minter \union {
        [ caller_id |-> caller_id,
           response |-> Variant("SubmissionOk", UNIT)
        ]
    };
}

macro respond_btc_canister_to_minter_err(caller_id) {
    btc_canister_to_minter := btc_canister_to_minter \union { BTC_Canister_Error_Response(caller_id) };
}

macro reset_variables_heartbeat() {
        \* submitted := <<[request_id |-> 0, address |-> MINTER_CKBTC_ADDRESS, amount |-> 0]>>;
        submitted := <<>>;
        submitted_ids := <<>>;
        spent := {};
        outputs := <<>>;
        new_transaction := No_Submission;
}

macro return_from_update_balance() {
            locks := locks \ {caller_account.owner};
            caller_account := MINTER_CKBTC_ADDRESS;
            new_utxos := {};
            goto Update_Balance_Start;
}




\**********************************************************************************************
\* BTC network behavior
\**********************************************************************************************
process (BTC = BTC_PROCESS_ID)
    variable nr_user_transfers = 0;
{
BTC_Loop:
    while(TRUE) {
        either {
            \* A transfer from a user-controlled address to a minter-controlled one
            \* (up to MAX_USER_BTC_TRANSFERS of such transfers)
            await(nr_user_transfers < MAX_USER_BTC_TRANSFERS);
            with(user_utxos \in SUBSET Utxos_Owned_By(btc, {USER_BTC_ADDRESS});
                    dest_address \in Image(DEPOSIT_ADDRESS, CK_BTC_ADDRESSES \union {MINTER_CKBTC_ADDRESS});
                    dest_amount \in 1..Sum_Utxos(user_utxos);
                    transaction = [ consumed_utxos |-> user_utxos, outputs |-> New_Outputs(user_utxos, <<[address |-> dest_address, amount |-> dest_amount]>>, USER_BTC_ADDRESS) ];
                    local_new_utxos = Utxos_Of(transaction)
                    ) {
                btc := (btc \ user_utxos) \union local_new_utxos;
                nr_user_transfers := nr_user_transfers + 1;
            }
        } or {
            \* Apply a transaction sent by the BTC canister
            with(submission \in { s \in btc_canister_to_btc: s.consumed_utxos \subseteq btc };
                local_new_utxos = Utxos_Of(submission)) {
                btc_canister_to_btc := btc_canister_to_btc \ {submission};
                btc := local_new_utxos \union (btc \ submission.consumed_utxos);
            }
        }
    }
}

\**********************************************************************************************
\* BTC canister behavior
\**********************************************************************************************
process ( BTC_Canister = BTC_CANISTER_PROCESS_ID)
{
BTC_Canister_Loop:
while(TRUE) {
  either {
    \* Ingest the current BTC network status
    \* In practice, the ledger could also ingest an old state of the BTC network
    \* For us, this model should suffice, as we can get an equivalent behavior to
    \* the real world by changing the real world behavior to defer any changes to
    \* the BTC network before to until the BTC canister updates
    btc_canister := btc;
  } or {
    \* Process a message from the minter
    await(minter_to_btc_canister # <<>>);
    with(req = Head(minter_to_btc_canister)) {
      minter_to_btc_canister := Tail(minter_to_btc_canister);
      either {
        \* Process a get_utxos request
        if(Is_Get_Utxos_Request(req)) {
          with( addr = Get_Utxos_Request_Address(req)) {
              respond_btc_canister_to_minter_utxos(Caller(req),
                  Utxos_Owned_By(btc_canister, {addr}));
          }
        } else {
          if(Is_Submission_Request(req)) {
            with(submission = VariantGetUnsafe("Submission", req.request)) {
                \* Process a submission request
                btc_canister_to_btc := btc_canister_to_btc \union {submission};
                respond_btc_canister_to_minter_submission_ok(Caller(req));
            }
          } else {
            \* The request must either be a get_utxos or submission request; it's a modelling error
            \* if any other kind of request appears, so fail.
            assert(FALSE);
          }
        }
      } or {
        \* Non-deterministically choose to respond with an error, regardless of what
        \* the request was
        respond_btc_canister_to_minter_err(Caller(req))
      }
    }
  }
}
};

\**********************************************************************************************
\* The message handler of the ledger canister that processes requests to mint, burn and
\* transfer user ckBTC
\**********************************************************************************************
process (Ledger = LEDGER_PROCESS_ID)
{
Ledger_Loop:
    while(TRUE) {
        either {
            \* A user-initiated transaction of ckBTC
            with(src_address \in DOMAIN balance \intersect CK_BTC_ADDRESSES;
                    dest_address \in
                        CK_BTC_ADDRESSES
                        \union
                        { BURN_ADDRESS(p) :  p \in PRINCIPALS };
                    amnt \in 1..balance[src_address];
                    balance_with_default = balance @@ (dest_address :> 0)
                            ) {
                balance := Remove_Balance_If_Zero(src_address, [ balance_with_default EXCEPT ![src_address] = @ - amnt, ![dest_address] = @ + amnt ]);
            }
        }
        or {
            \* A request by the minter canister
            await(minter_to_ledger # <<>>);
            with(req = Head(minter_to_ledger)) {
                minter_to_ledger := Tail(minter_to_ledger);
                either {
                    if(Is_Mint_Request(req)) {
                        with(mint_req = VariantGetUnsafe("Mint", req.request)) {
                            balance := mint_req.to :> (With_Default(balance, mint_req.to, 0) + mint_req.amount)
                                @@ balance;
                            respond_ledger_to_minter(req.caller_id, Status_Ok);
                        }
                    } else {
                        if(Is_Burn_Request(req)) {
                            with(burn_req = VariantGetUnsafe("Burn", req.request)) {
                                if(burn_req.address \in DOMAIN balance /\ balance[burn_req.address] >= burn_req.amount) {
                                    balance := Remove_Balance_If_Zero(burn_req.address, [ balance EXCEPT ![burn_req.address] = @ - burn_req.amount]);
                                    respond_ledger_to_minter(Caller(req), Status_Ok);
                                } else {
                                    respond_ledger_to_minter(Caller(req), Status_Err);
                                }
                            }
                        } else {
                            assert(FALSE);
                        }
                    }
                } or {
                    \* Non-deterministically choose to send an error response
                    respond_ledger_to_minter(req.caller_id, Status_System_Err);
                };
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

\**********************************************************************************************
\* Model of the behavior of retrieve BTC calls
\**********************************************************************************************
process (Retrieve_BTC \in RETRIEVE_BTC_PROCESS_IDS)
    variable
        \* These variables model the parameters of the call. However, we don't model the choice of destination
        \* from the start, as this can be chosen later (we can ignore it if burning doesn't succeed),
        \* so that we don't have to keep it in the state. We also start with some default values, and
        \* choose their values only later, once we start running the method, to reduce the state space.
        amount = 0;
{
Retrieve_BTC_Start:
    \* Choose parameters and send a burn message to the ledger
    with(user \in PRINCIPALS; amt \in 1..BTC_SUPPLY) {
        amount := amt;
        send_minter_to_ledger_burn(self, BURN_ADDRESS(user), amount);
    };
Retrieve_BTC_Wait_Burn:
    \* Receive the ledger response
    with(response \in { r \in ledger_to_minter: Caller(r) = self }; status = Status(response);
        \* Disable transfers to the minter BTC address when doing liveness checking
        destination \in Image(DEPOSIT_ADDRESS, CK_BTC_ADDRESSES) \union { (* MINTER_CKBTC_ADDRESS , *) USER_BTC_ADDRESS};
        ) {
        ledger_to_minter := ledger_to_minter \ {response};
        if(Is_Ok(status)) {
            pending := Queue_Pending(pending, next_request_id, destination, amount);
            next_request_id := next_request_id + 1;
        } else {
            \* Just return an error to the user (not modelled here)
            skip;
        };
        \* Reset the arguments in order to reduce the state space
        amount := 0;

    }
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
    while(TRUE) {
        if (pending # <<>>) {
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
        } else goto Finalize_Requests;
    Conclude_Submission:
    with(response \in { r \in btc_canister_to_minter: Caller(r) = self }; change_index \in {i\in DOMAIN outputs : outputs[i].owner = DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS]}) {
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
    with(response \in { r \in btc_canister_to_minter: Caller(r) = self };
            ) {
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
}

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "3da9ec41" /\ chksum(tla) = "65ef999d")
VARIABLES pc, btc, btc_canister, utxos_state_addresses, available_utxos, 
          finalized_utxos, locks, pending, submitted_transactions, balance, 
          btc_canister_to_btc, minter_to_btc_canister, btc_canister_to_minter, 
          minter_to_ledger, ledger_to_minter, next_request_id, resubmit_count, 
          nr_user_transfers, caller_account, new_utxos, amount, submitted, 
          submitted_ids, spent, outputs, new_transaction

vars == << pc, btc, btc_canister, utxos_state_addresses, available_utxos, 
           finalized_utxos, locks, pending, submitted_transactions, balance, 
           btc_canister_to_btc, minter_to_btc_canister, 
           btc_canister_to_minter, minter_to_ledger, ledger_to_minter, 
           next_request_id, resubmit_count, nr_user_transfers, caller_account, 
           new_utxos, amount, submitted, submitted_ids, spent, outputs, 
           new_transaction >>

ProcSet == {BTC_PROCESS_ID} \cup {BTC_CANISTER_PROCESS_ID} \cup {LEDGER_PROCESS_ID} \cup (UPDATE_BALANCE_PROCESS_IDS) \cup (RETRIEVE_BTC_PROCESS_IDS) \cup (HEARTBEAT_PROCESS_IDS)

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
        /\ resubmit_count = 1
        (* Process BTC *)
        /\ nr_user_transfers = 0
        (* Process Update_Balance *)
        /\ caller_account = [self \in UPDATE_BALANCE_PROCESS_IDS |-> MINTER_CKBTC_ADDRESS]
        /\ new_utxos = [self \in UPDATE_BALANCE_PROCESS_IDS |-> {}]
        (* Process Retrieve_BTC *)
        /\ amount = [self \in RETRIEVE_BTC_PROCESS_IDS |-> 0]
        (* Process Heartbeat *)
        /\ submitted = [self \in HEARTBEAT_PROCESS_IDS |-> <<>>]
        /\ submitted_ids = [self \in HEARTBEAT_PROCESS_IDS |-> <<>>]
        /\ spent = [self \in HEARTBEAT_PROCESS_IDS |-> {}]
        /\ outputs = [self \in HEARTBEAT_PROCESS_IDS |-> <<>>]
        /\ new_transaction = [self \in HEARTBEAT_PROCESS_IDS |-> No_Submission]
        /\ pc = [self \in ProcSet |-> CASE self = BTC_PROCESS_ID -> "BTC_Loop"
                                        [] self = BTC_CANISTER_PROCESS_ID -> "BTC_Canister_Loop"
                                        [] self = LEDGER_PROCESS_ID -> "Ledger_Loop"
                                        [] self \in UPDATE_BALANCE_PROCESS_IDS -> "Update_Balance_Start"
                                        [] self \in RETRIEVE_BTC_PROCESS_IDS -> "Retrieve_BTC_Start"
                                        [] self \in HEARTBEAT_PROCESS_IDS -> "Heartbeat_Start"]

BTC_Loop == /\ pc[BTC_PROCESS_ID] = "BTC_Loop"
            /\ \/ /\ (nr_user_transfers < MAX_USER_BTC_TRANSFERS)
                  /\ \E user_utxos \in SUBSET Utxos_Owned_By(btc, {USER_BTC_ADDRESS}):
                       \E dest_address \in Image(DEPOSIT_ADDRESS, CK_BTC_ADDRESSES \union {MINTER_CKBTC_ADDRESS}):
                         \E dest_amount \in 1..Sum_Utxos(user_utxos):
                           LET transaction == [ consumed_utxos |-> user_utxos, outputs |-> New_Outputs(user_utxos, <<[address |-> dest_address, amount |-> dest_amount]>>, USER_BTC_ADDRESS) ] IN
                             LET local_new_utxos == Utxos_Of(transaction) IN
                               /\ btc' = ((btc \ user_utxos) \union local_new_utxos)
                               /\ nr_user_transfers' = nr_user_transfers + 1
                  /\ UNCHANGED btc_canister_to_btc
               \/ /\ \E submission \in { s \in btc_canister_to_btc: s.consumed_utxos \subseteq btc }:
                       LET local_new_utxos == Utxos_Of(submission) IN
                         /\ btc_canister_to_btc' = btc_canister_to_btc \ {submission}
                         /\ btc' = (local_new_utxos \union (btc \ submission.consumed_utxos))
                  /\ UNCHANGED nr_user_transfers
            /\ pc' = [pc EXCEPT ![BTC_PROCESS_ID] = "BTC_Loop"]
            /\ UNCHANGED << btc_canister, utxos_state_addresses, 
                            available_utxos, finalized_utxos, locks, pending, 
                            submitted_transactions, balance, 
                            minter_to_btc_canister, btc_canister_to_minter, 
                            minter_to_ledger, ledger_to_minter, 
                            next_request_id, resubmit_count, caller_account, 
                            new_utxos, amount, submitted, submitted_ids, spent, 
                            outputs, new_transaction >>

BTC == BTC_Loop

BTC_Canister_Loop == /\ pc[BTC_CANISTER_PROCESS_ID] = "BTC_Canister_Loop"
                     /\ \/ /\ btc_canister' = btc
                           /\ UNCHANGED <<btc_canister_to_btc, minter_to_btc_canister, btc_canister_to_minter>>
                        \/ /\ (minter_to_btc_canister # <<>>)
                           /\ LET req == Head(minter_to_btc_canister) IN
                                /\ minter_to_btc_canister' = Tail(minter_to_btc_canister)
                                /\ \/ /\ IF Is_Get_Utxos_Request(req)
                                            THEN /\ LET addr == Get_Utxos_Request_Address(req) IN
                                                      btc_canister_to_minter' = (btc_canister_to_minter \union { Get_Utxos_Response((Caller(req)), (Utxos_Owned_By(btc_canister, {addr}))) })
                                                 /\ UNCHANGED btc_canister_to_btc
                                            ELSE /\ IF Is_Submission_Request(req)
                                                       THEN /\ LET submission == VariantGetUnsafe("Submission", req.request) IN
                                                                 /\ btc_canister_to_btc' = (btc_canister_to_btc \union {submission})
                                                                 /\ btc_canister_to_minter' = (                          btc_canister_to_minter \union {
                                                                                                   [ caller_id |-> (Caller(req)),
                                                                                                      response |-> Variant("SubmissionOk", UNIT)
                                                                                                   ]
                                                                                               })
                                                       ELSE /\ Assert((FALSE), 
                                                                      "Failure of assertion at line 506, column 13.")
                                                            /\ UNCHANGED << btc_canister_to_btc, 
                                                                            btc_canister_to_minter >>
                                   \/ /\ btc_canister_to_minter' = (btc_canister_to_minter \union { BTC_Canister_Error_Response((Caller(req))) })
                                      /\ UNCHANGED btc_canister_to_btc
                           /\ UNCHANGED btc_canister
                     /\ pc' = [pc EXCEPT ![BTC_CANISTER_PROCESS_ID] = "BTC_Canister_Loop"]
                     /\ UNCHANGED << btc, utxos_state_addresses, 
                                     available_utxos, finalized_utxos, locks, 
                                     pending, submitted_transactions, balance, 
                                     minter_to_ledger, ledger_to_minter, 
                                     next_request_id, resubmit_count, 
                                     nr_user_transfers, caller_account, 
                                     new_utxos, amount, submitted, 
                                     submitted_ids, spent, outputs, 
                                     new_transaction >>

BTC_Canister == BTC_Canister_Loop

Ledger_Loop == /\ pc[LEDGER_PROCESS_ID] = "Ledger_Loop"
               /\ \/ /\ \E src_address \in DOMAIN balance \intersect CK_BTC_ADDRESSES:
                          \E dest_address \in CK_BTC_ADDRESSES
                                              \union
                                              { BURN_ADDRESS(p) :  p \in PRINCIPALS }:
                            \E amnt \in 1..balance[src_address]:
                              LET balance_with_default == balance @@ (dest_address :> 0) IN
                                balance' = Remove_Balance_If_Zero(src_address, [ balance_with_default EXCEPT ![src_address] = @ - amnt, ![dest_address] = @ + amnt ])
                     /\ UNCHANGED <<minter_to_ledger, ledger_to_minter>>
                  \/ /\ (minter_to_ledger # <<>>)
                     /\ LET req == Head(minter_to_ledger) IN
                          /\ minter_to_ledger' = Tail(minter_to_ledger)
                          /\ \/ /\ IF Is_Mint_Request(req)
                                      THEN /\ LET mint_req == VariantGetUnsafe("Mint", req.request) IN
                                                /\ balance' = (       mint_req.to :> (With_Default(balance, mint_req.to, 0) + mint_req.amount)
                                                               @@ balance)
                                                /\ ledger_to_minter' = (ledger_to_minter \union { [ caller_id |-> (req.caller_id), status |-> Status_Ok ] })
                                      ELSE /\ IF Is_Burn_Request(req)
                                                 THEN /\ LET burn_req == VariantGetUnsafe("Burn", req.request) IN
                                                           IF burn_req.address \in DOMAIN balance /\ balance[burn_req.address] >= burn_req.amount
                                                              THEN /\ balance' = Remove_Balance_If_Zero(burn_req.address, [ balance EXCEPT ![burn_req.address] = @ - burn_req.amount])
                                                                   /\ ledger_to_minter' = (ledger_to_minter \union { [ caller_id |-> (Caller(req)), status |-> Status_Ok ] })
                                                              ELSE /\ ledger_to_minter' = (ledger_to_minter \union { [ caller_id |-> (Caller(req)), status |-> Status_Err ] })
                                                                   /\ UNCHANGED balance
                                                 ELSE /\ Assert((FALSE), 
                                                                "Failure of assertion at line 563, column 29.")
                                                      /\ UNCHANGED << balance, 
                                                                      ledger_to_minter >>
                             \/ /\ ledger_to_minter' = (ledger_to_minter \union { [ caller_id |-> (req.caller_id), status |-> Status_System_Err ] })
                                /\ UNCHANGED balance
               /\ pc' = [pc EXCEPT ![LEDGER_PROCESS_ID] = "Ledger_Loop"]
               /\ UNCHANGED << btc, btc_canister, utxos_state_addresses, 
                               available_utxos, finalized_utxos, locks, 
                               pending, submitted_transactions, 
                               btc_canister_to_btc, minter_to_btc_canister, 
                               btc_canister_to_minter, next_request_id, 
                               resubmit_count, nr_user_transfers, 
                               caller_account, new_utxos, amount, submitted, 
                               submitted_ids, spent, outputs, new_transaction >>

Ledger == Ledger_Loop

Update_Balance_Start(self) == /\ pc[self] = "Update_Balance_Start"
                              /\ \E param_address \in CK_BTC_ADDRESSES:
                                   /\ caller_account' = [caller_account EXCEPT ![self] = param_address]
                                   /\ (param_address.owner \notin locks)
                                   /\ locks' = (locks \union {caller_account'[self].owner})
                                   /\ minter_to_btc_canister' =                       Append(minter_to_btc_canister,
                                                                Get_Utxos_Request(self, DEPOSIT_ADDRESS[caller_account'[self]]))
                              /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Receive_Utxos"]
                              /\ UNCHANGED << btc, btc_canister, 
                                              utxos_state_addresses, 
                                              available_utxos, finalized_utxos, 
                                              pending, submitted_transactions, 
                                              balance, btc_canister_to_btc, 
                                              btc_canister_to_minter, 
                                              minter_to_ledger, 
                                              ledger_to_minter, 
                                              next_request_id, resubmit_count, 
                                              nr_user_transfers, new_utxos, 
                                              amount, submitted, submitted_ids, 
                                              spent, outputs, new_transaction >>

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
                                      /\ UNCHANGED << btc, btc_canister, 
                                                      utxos_state_addresses, 
                                                      available_utxos, pending, 
                                                      submitted_transactions, 
                                                      balance, 
                                                      btc_canister_to_btc, 
                                                      minter_to_btc_canister, 
                                                      ledger_to_minter, 
                                                      next_request_id, 
                                                      resubmit_count, 
                                                      nr_user_transfers, 
                                                      amount, submitted, 
                                                      submitted_ids, spent, 
                                                      outputs, new_transaction >>

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
                                    /\ UNCHANGED << btc, btc_canister, 
                                                    finalized_utxos, pending, 
                                                    submitted_transactions, 
                                                    balance, 
                                                    btc_canister_to_btc, 
                                                    minter_to_btc_canister, 
                                                    btc_canister_to_minter, 
                                                    minter_to_ledger, 
                                                    next_request_id, 
                                                    resubmit_count, 
                                                    nr_user_transfers, amount, 
                                                    submitted, submitted_ids, 
                                                    spent, outputs, 
                                                    new_transaction >>

Update_Balance(self) == Update_Balance_Start(self)
                           \/ Update_Balance_Receive_Utxos(self)
                           \/ Update_Balance_Mark_Minted(self)

Retrieve_BTC_Start(self) == /\ pc[self] = "Retrieve_BTC_Start"
                            /\ \E user \in PRINCIPALS:
                                 \E amt \in 1..BTC_SUPPLY:
                                   /\ amount' = [amount EXCEPT ![self] = amt]
                                   /\ minter_to_ledger' = Append(minter_to_ledger, Burn_Request(self, (BURN_ADDRESS(user)), amount'[self]))
                            /\ pc' = [pc EXCEPT ![self] = "Retrieve_BTC_Wait_Burn"]
                            /\ UNCHANGED << btc, btc_canister, 
                                            utxos_state_addresses, 
                                            available_utxos, finalized_utxos, 
                                            locks, pending, 
                                            submitted_transactions, balance, 
                                            btc_canister_to_btc, 
                                            minter_to_btc_canister, 
                                            btc_canister_to_minter, 
                                            ledger_to_minter, next_request_id, 
                                            resubmit_count, nr_user_transfers, 
                                            caller_account, new_utxos, 
                                            submitted, submitted_ids, spent, 
                                            outputs, new_transaction >>

Retrieve_BTC_Wait_Burn(self) == /\ pc[self] = "Retrieve_BTC_Wait_Burn"
                                /\ \E response \in { r \in ledger_to_minter: Caller(r) = self }:
                                     LET status == Status(response) IN
                                       \E destination \in Image(DEPOSIT_ADDRESS, CK_BTC_ADDRESSES) \union {                              USER_BTC_ADDRESS}:
                                         /\ ledger_to_minter' = ledger_to_minter \ {response}
                                         /\ IF Is_Ok(status)
                                               THEN /\ pending' = Queue_Pending(pending, next_request_id, destination, amount[self])
                                                    /\ next_request_id' = next_request_id + 1
                                               ELSE /\ TRUE
                                                    /\ UNCHANGED << pending, 
                                                                    next_request_id >>
                                         /\ amount' = [amount EXCEPT ![self] = 0]
                                /\ pc' = [pc EXCEPT ![self] = "Done"]
                                /\ UNCHANGED << btc, btc_canister, 
                                                utxos_state_addresses, 
                                                available_utxos, 
                                                finalized_utxos, locks, 
                                                submitted_transactions, 
                                                balance, btc_canister_to_btc, 
                                                minter_to_btc_canister, 
                                                btc_canister_to_minter, 
                                                minter_to_ledger, 
                                                resubmit_count, 
                                                nr_user_transfers, 
                                                caller_account, new_utxos, 
                                                submitted, submitted_ids, 
                                                spent, outputs, 
                                                new_transaction >>

Retrieve_BTC(self) == Retrieve_BTC_Start(self)
                         \/ Retrieve_BTC_Wait_Burn(self)

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
                                         next_request_id, resubmit_count, 
                                         nr_user_transfers, caller_account, 
                                         new_utxos, amount >>

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
                                             ledger_to_minter, next_request_id, 
                                             resubmit_count, nr_user_transfers, 
                                             caller_account, new_utxos, amount >>

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
                                           next_request_id, resubmit_count, 
                                           nr_user_transfers, caller_account, 
                                           new_utxos, amount, submitted, 
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
                                              next_request_id, resubmit_count, 
                                              nr_user_transfers, 
                                              caller_account, new_utxos, 
                                              amount >>

Heartbeat(self) == Heartbeat_Start(self) \/ Conclude_Submission(self)
                      \/ Finalize_Requests(self)
                      \/ Receive_Change_Utxos(self)

Next == BTC \/ BTC_Canister \/ Ledger
           \/ (\E self \in UPDATE_BALANCE_PROCESS_IDS: Update_Balance(self))
           \/ (\E self \in RETRIEVE_BTC_PROCESS_IDS: Retrieve_BTC(self))
           \/ (\E self \in HEARTBEAT_PROCESS_IDS: Heartbeat(self))

Spec == Init /\ [][Next]_vars

\* END TRANSLATION

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
        /\ BTC_Canister_Loop
        /\ minter_to_btc_canister # <<>>
        /\ minter_to_btc_canister' # minter_to_btc_canister
        /\ Is_Submission_Request(Head(minter_to_btc_canister))
        /\ LET req_pid == Caller(Head(minter_to_btc_canister)) IN
                \A resp \in btc_canister_to_minter': Caller(resp) = req_pid => VariantTag(resp.response) = "SubmissionOk"
       )
    /\ \A addr \in CK_BTC_ADDRESSES \union {MINTER_CKBTC_ADDRESS}: SF_vars(
        /\ BTC_Canister_Loop
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
        /\ Ledger_Loop
        /\ minter_to_ledger # <<>>
        /\ minter_to_ledger' # minter_to_ledger
        /\ {} = { r \in ledger_to_minter' :
            /\ Caller(r) = Caller(Head(minter_to_ledger))
            /\ Is_System_Err(Status(r)) }
        )
    \* Fairness of the BTC network processing the BTC canister messages. Weak fairness is
    \* enough here, as BTC network doesn't return errors.
    /\ WF_vars(BTC_Loop /\ btc_canister_to_btc # {} /\ btc_canister_to_btc' # btc_canister_to_btc)
    \* We also want the BTC canister to not postpone refreshing its view of BTC network forever
    /\ WF_vars(
        /\ BTC_Canister_Loop
        /\ btc_canister # btc
        /\ btc_canister' = btc
       )
    \* Fairness of balance updates: for each address addr, we will start Update_Balance
    \* infinitely often with that address chosen as the argument. We use strong fairness as
    \* a step that chooses a different addr' may (temporarily) disable Update_Balance
    /\ \A addr \in CK_BTC_ADDRESSES: SF_vars(\E pid \in UPDATE_BALANCE_PROCESS_IDS:
            /\ Update_Balance(pid)
            /\ pc[pid] = "Update_Balance_Start"
            /\ caller_account'[pid] = addr
        )
    \* Additionally, we want weak fairness for the remaining Update_Balance steps (they
    \* can't be ignored forever if they are enabled)

    /\ \A pid \in UPDATE_BALANCE_PROCESS_IDS: WF_vars(Update_Balance(pid))
    /\ \A pid \in RETRIEVE_BTC_PROCESS_IDS: WF_vars(Retrieve_BTC(pid))
    (* /\ \A pid \in RESUBMIT_RETRIEVE_BTC_PROCESS_IDS: WF_vars(Resubmit_Retrieve_BTC(pid)) *)
    /\ \A pid \in HEARTBEAT_PROCESS_IDS: WF_vars(Heartbeat(pid))

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


Liveness_Spec ==
    /\ Init
    /\ [][Next /\ Prevent_Donations_To_Change_Address]_vars
    /\ Fairness_Condition

====
