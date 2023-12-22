This is an abstract model of the main data flows in chain key Bitcoin (ckBTC): updating balance, 
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

---- MODULE Ck_BTC ----
EXTENDS TLC, Sequences, Integers, FiniteSets, FiniteSetsExt, SequencesExt, Functions, TLA_Hash

\**********************************************************************************************
(* Some general auxiliary definitions on sets, functions etc. *)
\**********************************************************************************************

Proper_Subsets(S) == SUBSET S \ {S}

Sum_F(f(_), S) == FoldSet(LAMBDA x, y: f(x) + y, 0, S)

With_Default(f, x, default) == IF x \in DOMAIN f THEN f[x] ELSE default
Remove_Arguments(f, S) == [ x \in (DOMAIN f \ S) |-> f[x] ]
Remove_Argument(f, x) == Remove_Arguments(f, {x})

Empty_Fun == [ x \in {} |-> {} ]

\**********************************************************************************************
(* Constants of the model *)
\**********************************************************************************************
CONSTANTS 
    \**********************************************************************************************
    \* Constants determining the model size
    \**********************************************************************************************
    \* User addresses under the control of the minter; we assume a finite number of such
    \* addresses, to keep the state space bounded.
    \* @type: Set(BTC_ADDRESS);
    CK_BTC_ADDRESSES,
    \* Every BTC transfer allocates a new UTXO id. Allowing an infinite number of transfers
    \* would thus require infinite state. So we bound the number of BTC transfers a user is
    \* allowed to make.
    \* @type: Int;
    MAX_USER_BTC_TRANSFERS,
    \* Initial "supply" of BTC (all allocated to the user account initially)
    \* @type: Int;
    BTC_SUPPLY,
    \* The set of process IDs for the update balance processes.
    \* The cardinality of the set effectively determines the number of concurrent calls 
    \* to the update_balance method on the minter canister.
    \* @type: Set(PID);
    UPDATE_BALANCE_PROCESS_IDS,
    \* The set of process IDs for Retrieve_BTC process.
    \* This roughly, corresponding to the set of call contexts for the retrieve_btc method,
    \* and limits the number of times that retrieve_btc can be called.
    \* @type: Set(PID);
    RETRIEVE_BTC_PROCESS_IDS,
    \* Same as for retrieve_btc, just for the resubmit_retrieve_btc minter method.
    \* @type: Set(PID);
    RESUBMIT_RETRIEVE_BTC_PROCESS_IDS,
    \**********************************************************************************************
    \* Other constants
    \**********************************************************************************************
    \* The "user-controlled" BTC address; we assume just one such address in this model.
    \* @type: BTC_ADDRESS;
    USER_BTC_ADDRESS,
    \* The special minter BTC address (for collecting retrieval change).
    \* @type: BTC_ADDRESS;
    MINTER_BTC_ADDRESS,
    \* The ID of the PlusCal process simulating the BTC network
    \* @type: PID;
    BTC_PROCESS_ID,
    \* The ID of the PlusCal process simulating the ckBTC Ledger
    \* @type: PID;
    LEDGER_PROCESS_ID,
    \* The ID of the PlusCal process simulating the BTC canister
    \* @type: PID;
    BTC_CANISTER_PROCESS_ID,
    \* The ID of the PlusCal process simulating the heartbeat of the ckBTC Ledger
    \* @type: PID;
    HEARTBEAT_PROCESS_ID,
    \* Converts a user CK_BTC address to a ckBTC ledger withdrawal address
    \* @type: BTC_ADDRESS -> WITHDRAWAL_ADDR;
    BTC_TO_WITHDRAWAL(_)

\**********************************************************************************************
\* Constants used when running the analysis using the TLC tool
\**********************************************************************************************

\* The version of BTC_TO_WITHDRAWAL used with TLC for analysis, as TLC doesn't care about types
BTC_To_W(btc_addr) == << "w", btc_addr >>

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
Symmetry_Sets == { CK_BTC_ADDRESSES, UPDATE_BALANCE_PROCESS_IDS, RETRIEVE_BTC_PROCESS_IDS, RESUBMIT_RETRIEVE_BTC_PROCESS_IDS }
Symmetry_Permutations == UNION { Permutations(S) : S \in Symmetry_Sets }


\**********************************************************************************************
\* Auxiliary definitions
\**********************************************************************************************

\* Definitions on UTXO sets
Sum_Utxos(S) == Sum_F(LAMBDA x: x.amount, S)
Utxos_Owned_By(utxos, S) == { utxo \in utxos: utxo.owner \in S }

\* Utility definitions to deal with the fields in utxos_states_addresses values
New_Address_State == [discovered_utxos |-> {}, processed_utxos |-> {}, spent_utxos |-> {}]
Discovered_Utxos(addr_to_state, addr) == With_Default(addr_to_state, addr, New_Address_State).discovered_utxos
Processed_Utxos(addr_to_state, addr) == With_Default(addr_to_state, addr, New_Address_State).processed_utxos
Spent_Utxos(addr_to_state, addr) == With_Default(addr_to_state, addr, New_Address_State).spent_utxos
Set_Discovered_Utxos(addr_to_state, addr, utxos) == 
    addr :> [ discovered_utxos |-> utxos, 
              processed_utxos |-> With_Default(addr_to_state, addr, New_Address_State).processed_utxos,
              spent_utxos |-> With_Default(addr_to_state, addr, New_Address_State).spent_utxos
            ]
    @@ addr_to_state
Set_Processed_Utxos(addr_to_state, addr, utxos) == 
    addr :> [ discovered_utxos |-> With_Default(addr_to_state, addr, New_Address_State).discovered_utxos, 
              processed_utxos |-> utxos,
              spent_utxos |-> With_Default(addr_to_state, addr, New_Address_State).spent_utxos ]
    @@ addr_to_state
Set_Spent_Utxos(addr_to_state, addr, utxos) == 
    addr :> [ discovered_utxos |-> With_Default(addr_to_state, addr, New_Address_State).discovered_utxos, 
              processed_utxos |-> With_Default(addr_to_state, addr, New_Address_State).processed_utxos,
              spent_utxos |-> utxos ]
    @@ addr_to_state

\* "Standard" inter-canister message definitions, used for communication between any pair of canisters.
\* E.g., whether a response is an error or not, what the PID of the caller of a request is, etc.
Status_Ok == "OK"
Status_Err == "Err"
Status_System_Err == "System_Err"
Is_Ok(status) == status = Status_Ok
Is_System_Err(status) == status = Status_System_Err

Caller(msg) == msg.caller_id
Status(msg) == msg.status
Error_Response(caller_id) == [ caller_id |-> caller_id, status |-> Status_Err ]

\* Auxiliary definitions for specific kinds of messages (e.g., a get_utxos request)
Get_Utxos_Request(caller_id, btc_address) == [
    caller_id |-> caller_id,
    type |-> "get_utxos",
    address |-> btc_address
]
Is_Get_Utxos_Request(req) == req.type = "get_utxos"
Get_Utxos_Request_Address(req) == req.address
Get_Utxos_Response(caller_id, utxos) == [ caller_id |-> caller_id, utxos |-> utxos, status |-> Status_Ok ]
Get_Utxos_Result(response) == response.utxos

New_Submission(consumed_utxos, outputs, other_data) ==
    [ consumed_utxos |-> consumed_utxos, outputs |-> outputs, other_data |-> other_data ]

Submission_Request(caller_id, submission) == [ 
    type |-> "submit",
    caller_id |-> caller_id, 
    submission |-> submission ]
Is_Submission_Request(req) == req.type = "submit"

Mint_Request(caller_id, to_address, amount) == [ 
    type |-> "mint", caller_id |-> caller_id, to |-> to_address, amount |-> amount 
]
Is_Mint_Request(req) == req.type = "mint"

Burn_Request(caller_id, address, amount) == [ 
    type |-> "burn", caller_id |-> caller_id, address |-> address, amount |-> amount
]
Is_Burn_Request(req) == req.type = "burn"

\* Other auxiliary definitions

\* Put a submission at the end of the minter's "pending" queue
Queue_Pending(pending, request_id, address, amount) == Append(pending, 
    [ request_id |-> request_id, address |-> address, amount |-> amount ])

\* Given a value like utxos_states_addresses, get all processed UTXOs
All_Processed_Utxos(addresses) == 
    (UNION { Processed_Utxos(addresses, addr) : addr \in DOMAIN addresses })
\* Like above, but compute the sum
Available_Processed_Amount(addresses) == 
    Sum_Utxos(All_Processed_Utxos(addresses))

\* Compute the new outputs needed to transfer the money to the destination and handle change
New_Outputs(utxos, dest_address, amount, change_address) == 
    LET
        total == Sum_Utxos(utxos)
        change == total - amount
        parent_ids == { utxo.id : utxo \in utxos }
        assertion == Assert(change >= 0, 
            "Asked to create new outputs but provided insufficient funds for the amount requested")
    IN
        << [ owner |-> dest_address, amount |-> amount ] >> \o
            IF change > 0 THEN << [ owner |-> change_address, amount |-> change ] >> ELSE << >>

Utxos_Of(transaction) ==
    LET
        tx_hash == Hash(transaction)
    IN
        { [id |-> << tx_hash, i >> ] @@ transaction.outputs[i] : i \in 1..Len(transaction.outputs) }

\* Remove a set of utxos from the processed set of all utxos_states_addresses
Remove_From_Processed(addresses, utxos) == [ x \in DOMAIN addresses |-> [ addresses[x] EXCEPT !.processed_utxos = @ \ utxos ] ]
\* Add a set of UTXOs to the spent set of all utxos_states_addresses, at the correct index.
Add_To_Spent(addresses, utxos) == [ x \in DOMAIN addresses |-> [ addresses[x] EXCEPT !.spent_utxos = @ \union Utxos_Owned_By(utxos, {x}) ] ]

\* Remove a key from the balance map (i.e., undefine the partial function for that key) if its value is 0.
Remove_Balance_If_Zero(addr, b) == IF addr \in DOMAIN b /\ b[addr] = 0 THEN Remove_Argument(b, addr) ELSE b

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
    btc = { [ id |-> << 0 >>, owner |-> USER_BTC_ADDRESS, amount |-> BTC_SUPPLY ] };
    \**********************************************************************************************
    \* BTC Canister
    \**********************************************************************************************
    \* The state of the BTC canister, also as just a set of UTXOs. It's a
    \* snapshot of the BTC network state at some point in time.
    btc_canister = {};
    \**********************************************************************************************
    \* BTC library state (part of the minter canister state)
    \**********************************************************************************************
    \* Library state within the minter
    utxos_states_addresses = Empty_Fun;
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
    \* Sent requests. This is a combination of minter and library state, as it models both the 
    \* minter's requests_sent variable, and the library's in-flight transactions.
    requests_sent = Empty_Fun;
    \**********************************************************************************************
    \* ckBTC Ledger state
    \**********************************************************************************************
    \* The ledger is represented just through its mapping of balances
    balance = Empty_Fun;
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
        Get_Utxos_Request(caller_id, address));
}

macro send_minter_to_btc_canister_submit(caller_id, submission) {
    minter_to_btc_canister := Append(minter_to_btc_canister,
        Submission_Request(caller_id, submission));
}

macro respond_btc_canister_to_minter_utxos(caller_id, utxos) {
    btc_canister_to_minter := btc_canister_to_minter \union { Get_Utxos_Response(caller_id, utxos) };
}

macro respond_btc_canister_to_minter_ok(caller_id) {
    btc_canister_to_minter := btc_canister_to_minter \union {[ caller_id |-> caller_id, status |-> Status_Ok ]};
}

macro respond_btc_canister_to_minter_err(caller_id) {
    btc_canister_to_minter := btc_canister_to_minter \union { Error_Response(caller_id) };
}

\* A separate procedure for running the submission, such that it can actually be called
\* from multiple places.
procedure try_submit()
    variables 
        submitted = [request_id |-> 0, address |-> MINTER_BTC_ADDRESS, amount |-> 0];
        spent = {};
        outputs = <<>>;
{
\* Retrieve any new UTXOs for the "change" address and put them in the processed set for the address
Get_Change_Utxos:
    send_minter_to_btc_canister_get_utxos(self, MINTER_BTC_ADDRESS);
Receive_Change_Utxos:
    with(response \in { r \in btc_canister_to_minter: Caller(r) = self }; 
            status = Status(response)) {
        btc_canister_to_minter := btc_canister_to_minter \ {response};
        if(Is_Ok(status)) {
            utxos_states_addresses := Set_Processed_Utxos(utxos_states_addresses, MINTER_BTC_ADDRESS, Get_Utxos_Result(response));
        } else {
            return;
        }
    };
Start_Submission:
    if(pending = <<>>) {
        return;
    } else {
        with(submission = Head(pending); rest_pending = Tail(pending)) {
            if(Available_Processed_Amount(utxos_states_addresses) >= submission.amount) {
                \* Non-deterministically pick some subset of the processed UTXOs that have sufficient funds
                \* to submit the transaction
                with(sset \in {s \in SUBSET All_Processed_Utxos(utxos_states_addresses):
                        /\ Sum_Utxos(s) >= submission.amount 
                        /\ \A ps \in Proper_Subsets(s): Sum_Utxos(ps) < submission.amount };
                     new_outputs = New_Outputs(sset, submission.address, submission.amount, MINTER_BTC_ADDRESS)
                    ) {
                    pending := rest_pending;
                    submitted := submission;
                    spent := sset;
                    outputs := new_outputs;
                    send_minter_to_btc_canister_submit(self, New_Submission(sset, new_outputs, 0));
                }
            } else {
                return;
            }
        }
    };
Conclude_Submission:
    with(response \in { r \in btc_canister_to_minter: Caller(r) = self }; status = Status(response)){
        btc_canister_to_minter := btc_canister_to_minter \ {response};
        if(Is_Ok(status)) {
            utxos_states_addresses := 
                Remove_From_Processed(Add_To_Spent(utxos_states_addresses, spent), spent);

            requests_sent := submitted.request_id :> [spent |-> spent, outputs |-> outputs] @@ requests_sent;
            return;
        } else {
            \* This puts the submission at the end of the queue; 
            \* this corresponds to the plans for the implementation, though for the model's purposes
            \* we could also put this anywhere
            pending := Append(pending, submitted);
            return;
            \* TODO: what should we do about the transactions that we removed from the processed set
            \* and moved into spent?
        }
    }
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
                    dest_address \in CK_BTC_ADDRESSES \union {MINTER_BTC_ADDRESS};
                    dest_amount \in 1..Sum_Utxos(user_utxos); 
                    transaction = [ consumed_utxos |-> user_utxos, outputs |-> New_Outputs(user_utxos, dest_address, dest_amount, USER_BTC_ADDRESS) ];
                    new_utxos = Utxos_Of(transaction)
                    ) {
                btc := (btc \ user_utxos) \union new_utxos;
                nr_user_transfers := nr_user_transfers + 1;
            }
        } or {
            \* Apply a transaction sent by the BTC canister
            with(submission \in { s \in btc_canister_to_btc: s.consumed_utxos \subseteq btc };
                new_utxos = Utxos_Of(submission)) {
                btc_canister_to_btc := btc_canister_to_btc \ {submission};
                btc := new_utxos \union (btc \ submission.consumed_utxos);
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
                        with(addr = Get_Utxos_Request_Address(req)) {
                            respond_btc_canister_to_minter_utxos(Caller(req), 
                                Utxos_Owned_By(btc_canister, {addr}));
                        }
                    } else {
                        if(Is_Submission_Request(req)) {
                            \* Process a submission request
                            btc_canister_to_btc := btc_canister_to_btc \union {req.submission};
                            respond_btc_canister_to_minter_ok(Caller(req));
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
                        { BTC_TO_WITHDRAWAL(x) :  x \in CK_BTC_ADDRESSES };
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
                        balance := req.to :> (With_Default(balance, req.to, 0) + req.amount)
                            @@ balance;
                        respond_ledger_to_minter(req.caller_id, Status_Ok);
                    } else {
                        if(Is_Burn_Request(req)) {
                            if(req.address \in DOMAIN balance /\ balance[req.address] >= req.amount) {
                                balance := Remove_Balance_If_Zero(req.address, [ balance EXCEPT ![req.address] = @ - req.amount]);
                                respond_ledger_to_minter(Caller(req), Status_Ok);
                            } else {
                                respond_ledger_to_minter(Caller(req), Status_Err);
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
    variable ck_btc_address = MINTER_BTC_ADDRESS;
{
Update_Balance_Start:
    \* Non-deterministically pick a value for the argument
    with(param_address \in CK_BTC_ADDRESSES) {
        await(param_address \notin locks);
        ck_btc_address := param_address;
        locks := locks \union {ck_btc_address};
        send_minter_to_btc_canister_get_utxos(self, ck_btc_address);
    };
Update_Balance_Receive_Utxos:
    with(response \in { r \in btc_canister_to_minter: Caller(r) = self }; 
            status = Status(response)) {
        btc_canister_to_minter := btc_canister_to_minter \ {response};
        if(Is_Ok(status)) { with(utxos = Get_Utxos_Result(response)) {
            \* This is an invariant we can check at this particular time: when the get_utxos call
            \* (successfully) returns, the result should contain what we currently think are discovered utxos
            assert(Discovered_Utxos(utxos_states_addresses, ck_btc_address) \subseteq utxos);
            with(
                new_discovered = (utxos \ Processed_Utxos(utxos_states_addresses, ck_btc_address)) 
                    \ Spent_Utxos(utxos_states_addresses, ck_btc_address);
                \* Garbage collect the spent UTXOs, by keeping only those that are still showing
                \* up in the get_utxos call
                new_spent = Spent_Utxos(utxos_states_addresses, ck_btc_address) \intersect utxos
            ) {
                utxos_states_addresses := 
                    Set_Spent_Utxos(
                        Set_Discovered_Utxos(utxos_states_addresses, ck_btc_address, new_discovered),
                    ck_btc_address,
                    new_spent);
            };
            with(discovered_amount = Sum_Utxos(Discovered_Utxos(utxos_states_addresses, ck_btc_address))) {
                if(discovered_amount > 0) {
                    send_minter_to_ledger_mint(self, ck_btc_address, discovered_amount);
                } else {
                    \* If nothing new has been discovered, release the lock and finish
                    locks := locks \ {ck_btc_address};
                    ck_btc_address := MINTER_BTC_ADDRESS;
                    goto Update_Balance_Start;
                }
            }
        } } else {
            \* If the call fails, release the lock and finish
            locks := locks \ {ck_btc_address};
            ck_btc_address := MINTER_BTC_ADDRESS;
            goto Update_Balance_Start;
        }
    };
Update_Balance_Mark_Minted:
    with(response \in { r \in ledger_to_minter: Caller(r) = self};
            status = Status(response);
            processed = Processed_Utxos(utxos_states_addresses, ck_btc_address);
            discovered = Discovered_Utxos(utxos_states_addresses, ck_btc_address);
        ) {
        ledger_to_minter := ledger_to_minter \ {response};
        if(Is_Ok(status)) {
            utxos_states_addresses := 
                Set_Discovered_Utxos(
                    Set_Processed_Utxos(utxos_states_addresses, ck_btc_address, processed \union discovered),
                    ck_btc_address,
                    {}
                );
        };
    };
    \* Regardless of whether the call to the minter succeeds, release the lock
    locks := locks \ {ck_btc_address};
    \* To reduce the state space, reset the argument value when finishing the method
    ck_btc_address := MINTER_BTC_ADDRESS;
    goto Update_Balance_Start;
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
    with(addr \in CK_BTC_ADDRESSES; amt \in 1..BTC_SUPPLY) {
        amount := amt;
        send_minter_to_ledger_burn(self, BTC_TO_WITHDRAWAL(addr), amount);
    };
Retrieve_BTC_Wait_Burn:
    \* Receive the ledger response
    with(response \in { r \in ledger_to_minter: Caller(r) = self }; status = Status(response);
        \* Disable transfers to the minter BTC address when doing liveness checking
        destination \in CK_BTC_ADDRESSES \union { (* MINTER_BTC_ADDRESS , *) USER_BTC_ADDRESS};
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
\* Model of the behavior of the resubmit BTC call
\**********************************************************************************************
process (Resubmit_Retrieve_BTC \in RESUBMIT_RETRIEVE_BTC_PROCESS_IDS)
    \* We defer choosing the value of the argument of the call to the body,
    \* such that we can limit the choice to valid values and keep the state space in check
    variables 
        resubmit_request_id = 0;
        resubmission = Empty_Fun;
{
Start_Resubmit_Retrieve:
    with(request_id \in DOMAIN requests_sent \union { req.request_id: req \in { pending[i]: i \in DOMAIN pending } }) {
        if(request_id \in DOMAIN requests_sent) {
            with(
                \* This is a bit of a hack; the UTXO IDs of the resubmitted outputs differ from the old ones, because
                \* the new transaction has a different fee. As we don't model fees currently, we change a field of the
                \* submitted transaction (that will ultimately result in a different hash)
                new_submission = New_Submission(requests_sent[request_id].spent, requests_sent[request_id].outputs, resubmit_count)
            ) {
                resubmit_count := resubmit_count + 1;
                resubmit_request_id := request_id;
                resubmission := new_submission;
                send_minter_to_btc_canister_submit(self, new_submission);
            }
        } else {
            \* If the submission is still pending, the implementation just updates the associated fee.
            \* As we don't currently model the fee, there's nothing to do here.
            goto Done;
        }
    };
Conclude_Resubmission:
    with(response \in { r \in btc_canister_to_minter: Caller(r) = self }; status = Status(response)){
        btc_canister_to_minter := btc_canister_to_minter \ {response};
        if(Is_Ok(status)) {
            requests_sent := resubmit_request_id :> resubmission @@ requests_sent;
        } else {
            \* TODO: we probably just give out an error to the user here?
            skip;
        };
        \* Reset arguments to reduce the state space somewhat
        resubmit_request_id := 0;
        resubmission := Empty_Fun;
    }
}

\**********************************************************************************************
\* Model of the heartbeat on the minter canister.
\* We assume that heartbeats will implement locking, such that there is only one concurrent 
\* heartbeat that's not a no-op.
\* So we model the heartebat as a single process here running in an infinite loop.
\**********************************************************************************************
process (Heartbeat = HEARTBEAT_PROCESS_ID) 
{
Heartbeat_Start:
    while(TRUE) {
        await(pending # <<>>);
        call try_submit();
    }
}

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "141b0861" /\ chksum(tla) = "43a222ee")
VARIABLES btc, btc_canister, utxos_states_addresses, locks, pending, 
          requests_sent, balance, btc_canister_to_btc, minter_to_btc_canister, 
          btc_canister_to_minter, minter_to_ledger, ledger_to_minter, 
          next_request_id, resubmit_count, pc, stack, submitted, spent, 
          outputs, nr_user_transfers, ck_btc_address, amount, 
          resubmit_request_id, resubmission

vars == << btc, btc_canister, utxos_states_addresses, locks, pending, 
           requests_sent, balance, btc_canister_to_btc, 
           minter_to_btc_canister, btc_canister_to_minter, minter_to_ledger, 
           ledger_to_minter, next_request_id, resubmit_count, pc, stack, 
           submitted, spent, outputs, nr_user_transfers, ck_btc_address, 
           amount, resubmit_request_id, resubmission >>

ProcSet == {BTC_PROCESS_ID} \cup {BTC_CANISTER_PROCESS_ID} \cup {LEDGER_PROCESS_ID} \cup (UPDATE_BALANCE_PROCESS_IDS) \cup (RETRIEVE_BTC_PROCESS_IDS) \cup (RESUBMIT_RETRIEVE_BTC_PROCESS_IDS) \cup {HEARTBEAT_PROCESS_ID}

Init == (* Global variables *)
        /\ btc = { [ id |-> << 0 >>, owner |-> USER_BTC_ADDRESS, amount |-> BTC_SUPPLY ] }
        /\ btc_canister = {}
        /\ utxos_states_addresses = Empty_Fun
        /\ locks = {}
        /\ pending = <<>>
        /\ requests_sent = Empty_Fun
        /\ balance = Empty_Fun
        /\ btc_canister_to_btc = {}
        /\ minter_to_btc_canister = <<>>
        /\ btc_canister_to_minter = {}
        /\ minter_to_ledger = <<>>
        /\ ledger_to_minter = {}
        /\ next_request_id = 1
        /\ resubmit_count = 1
        (* Procedure try_submit *)
        /\ submitted = [ self \in ProcSet |-> [request_id |-> 0, address |-> MINTER_BTC_ADDRESS, amount |-> 0]]
        /\ spent = [ self \in ProcSet |-> {}]
        /\ outputs = [ self \in ProcSet |-> <<>>]
        (* Process BTC *)
        /\ nr_user_transfers = 0
        (* Process Update_Balance *)
        /\ ck_btc_address = [self \in UPDATE_BALANCE_PROCESS_IDS |-> MINTER_BTC_ADDRESS]
        (* Process Retrieve_BTC *)
        /\ amount = [self \in RETRIEVE_BTC_PROCESS_IDS |-> 0]
        (* Process Resubmit_Retrieve_BTC *)
        /\ resubmit_request_id = [self \in RESUBMIT_RETRIEVE_BTC_PROCESS_IDS |-> 0]
        /\ resubmission = [self \in RESUBMIT_RETRIEVE_BTC_PROCESS_IDS |-> Empty_Fun]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self = BTC_PROCESS_ID -> "BTC_Loop"
                                        [] self = BTC_CANISTER_PROCESS_ID -> "BTC_Canister_Loop"
                                        [] self = LEDGER_PROCESS_ID -> "Ledger_Loop"
                                        [] self \in UPDATE_BALANCE_PROCESS_IDS -> "Update_Balance_Start"
                                        [] self \in RETRIEVE_BTC_PROCESS_IDS -> "Retrieve_BTC_Start"
                                        [] self \in RESUBMIT_RETRIEVE_BTC_PROCESS_IDS -> "Start_Resubmit_Retrieve"
                                        [] self = HEARTBEAT_PROCESS_ID -> "Heartbeat_Start"]

Get_Change_Utxos(self) == /\ pc[self] = "Get_Change_Utxos"
                          /\ minter_to_btc_canister' =                       Append(minter_to_btc_canister,
                                                       Get_Utxos_Request(self, MINTER_BTC_ADDRESS))
                          /\ pc' = [pc EXCEPT ![self] = "Receive_Change_Utxos"]
                          /\ UNCHANGED << btc, btc_canister, 
                                          utxos_states_addresses, locks, 
                                          pending, requests_sent, balance, 
                                          btc_canister_to_btc, 
                                          btc_canister_to_minter, 
                                          minter_to_ledger, ledger_to_minter, 
                                          next_request_id, resubmit_count, 
                                          stack, submitted, spent, outputs, 
                                          nr_user_transfers, ck_btc_address, 
                                          amount, resubmit_request_id, 
                                          resubmission >>

Receive_Change_Utxos(self) == /\ pc[self] = "Receive_Change_Utxos"
                              /\ \E response \in { r \in btc_canister_to_minter: Caller(r) = self }:
                                   LET status == Status(response) IN
                                     /\ btc_canister_to_minter' = btc_canister_to_minter \ {response}
                                     /\ IF Is_Ok(status)
                                           THEN /\ utxos_states_addresses' = Set_Processed_Utxos(utxos_states_addresses, MINTER_BTC_ADDRESS, Get_Utxos_Result(response))
                                                /\ pc' = [pc EXCEPT ![self] = "Start_Submission"]
                                                /\ UNCHANGED << stack, 
                                                                submitted, 
                                                                spent, outputs >>
                                           ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                /\ submitted' = [submitted EXCEPT ![self] = Head(stack[self]).submitted]
                                                /\ spent' = [spent EXCEPT ![self] = Head(stack[self]).spent]
                                                /\ outputs' = [outputs EXCEPT ![self] = Head(stack[self]).outputs]
                                                /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                                /\ UNCHANGED utxos_states_addresses
                              /\ UNCHANGED << btc, btc_canister, locks, 
                                              pending, requests_sent, balance, 
                                              btc_canister_to_btc, 
                                              minter_to_btc_canister, 
                                              minter_to_ledger, 
                                              ledger_to_minter, 
                                              next_request_id, resubmit_count, 
                                              nr_user_transfers, 
                                              ck_btc_address, amount, 
                                              resubmit_request_id, 
                                              resubmission >>

Start_Submission(self) == /\ pc[self] = "Start_Submission"
                          /\ IF pending = <<>>
                                THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                     /\ submitted' = [submitted EXCEPT ![self] = Head(stack[self]).submitted]
                                     /\ spent' = [spent EXCEPT ![self] = Head(stack[self]).spent]
                                     /\ outputs' = [outputs EXCEPT ![self] = Head(stack[self]).outputs]
                                     /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                     /\ UNCHANGED << pending, 
                                                     minter_to_btc_canister >>
                                ELSE /\ LET submission == Head(pending) IN
                                          LET rest_pending == Tail(pending) IN
                                            IF Available_Processed_Amount(utxos_states_addresses) >= submission.amount
                                               THEN /\ \E sset \in       {s \in SUBSET All_Processed_Utxos(utxos_states_addresses):
                                                                   /\ Sum_Utxos(s) >= submission.amount
                                                                   /\ \A ps \in Proper_Subsets(s): Sum_Utxos(ps) < submission.amount }:
                                                         LET new_outputs == New_Outputs(sset, submission.address, submission.amount, MINTER_BTC_ADDRESS) IN
                                                           /\ pending' = rest_pending
                                                           /\ submitted' = [submitted EXCEPT ![self] = submission]
                                                           /\ spent' = [spent EXCEPT ![self] = sset]
                                                           /\ outputs' = [outputs EXCEPT ![self] = new_outputs]
                                                           /\ minter_to_btc_canister' =                       Append(minter_to_btc_canister,
                                                                                        Submission_Request(self, (New_Submission(sset, new_outputs, 0))))
                                                    /\ pc' = [pc EXCEPT ![self] = "Conclude_Submission"]
                                                    /\ stack' = stack
                                               ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                    /\ submitted' = [submitted EXCEPT ![self] = Head(stack[self]).submitted]
                                                    /\ spent' = [spent EXCEPT ![self] = Head(stack[self]).spent]
                                                    /\ outputs' = [outputs EXCEPT ![self] = Head(stack[self]).outputs]
                                                    /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                                    /\ UNCHANGED << pending, 
                                                                    minter_to_btc_canister >>
                          /\ UNCHANGED << btc, btc_canister, 
                                          utxos_states_addresses, locks, 
                                          requests_sent, balance, 
                                          btc_canister_to_btc, 
                                          btc_canister_to_minter, 
                                          minter_to_ledger, ledger_to_minter, 
                                          next_request_id, resubmit_count, 
                                          nr_user_transfers, ck_btc_address, 
                                          amount, resubmit_request_id, 
                                          resubmission >>

Conclude_Submission(self) == /\ pc[self] = "Conclude_Submission"
                             /\ \E response \in { r \in btc_canister_to_minter: Caller(r) = self }:
                                  LET status == Status(response) IN
                                    /\ btc_canister_to_minter' = btc_canister_to_minter \ {response}
                                    /\ IF Is_Ok(status)
                                          THEN /\ utxos_states_addresses' = Remove_From_Processed(Add_To_Spent(utxos_states_addresses, spent[self]), spent[self])
                                               /\ requests_sent' = (submitted[self].request_id :> [spent |-> spent[self], outputs |-> outputs[self]] @@ requests_sent)
                                               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                               /\ submitted' = [submitted EXCEPT ![self] = Head(stack[self]).submitted]
                                               /\ spent' = [spent EXCEPT ![self] = Head(stack[self]).spent]
                                               /\ outputs' = [outputs EXCEPT ![self] = Head(stack[self]).outputs]
                                               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                               /\ UNCHANGED pending
                                          ELSE /\ pending' = Append(pending, submitted[self])
                                               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                               /\ submitted' = [submitted EXCEPT ![self] = Head(stack[self]).submitted]
                                               /\ spent' = [spent EXCEPT ![self] = Head(stack[self]).spent]
                                               /\ outputs' = [outputs EXCEPT ![self] = Head(stack[self]).outputs]
                                               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                               /\ UNCHANGED << utxos_states_addresses, 
                                                               requests_sent >>
                             /\ UNCHANGED << btc, btc_canister, locks, balance, 
                                             btc_canister_to_btc, 
                                             minter_to_btc_canister, 
                                             minter_to_ledger, 
                                             ledger_to_minter, next_request_id, 
                                             resubmit_count, nr_user_transfers, 
                                             ck_btc_address, amount, 
                                             resubmit_request_id, resubmission >>

try_submit(self) == Get_Change_Utxos(self) \/ Receive_Change_Utxos(self)
                       \/ Start_Submission(self)
                       \/ Conclude_Submission(self)

BTC_Loop == /\ pc[BTC_PROCESS_ID] = "BTC_Loop"
            /\ \/ /\ (nr_user_transfers < MAX_USER_BTC_TRANSFERS)
                  /\ \E user_utxos \in SUBSET Utxos_Owned_By(btc, {USER_BTC_ADDRESS}):
                       \E dest_address \in CK_BTC_ADDRESSES \union {MINTER_BTC_ADDRESS}:
                         \E dest_amount \in 1..Sum_Utxos(user_utxos):
                           LET transaction == [ consumed_utxos |-> user_utxos, outputs |-> New_Outputs(user_utxos, dest_address, dest_amount, USER_BTC_ADDRESS) ] IN
                             LET new_utxos == Utxos_Of(transaction) IN
                               /\ btc' = ((btc \ user_utxos) \union new_utxos)
                               /\ nr_user_transfers' = nr_user_transfers + 1
                  /\ UNCHANGED btc_canister_to_btc
               \/ /\ \E submission \in { s \in btc_canister_to_btc: s.consumed_utxos \subseteq btc }:
                       LET new_utxos == Utxos_Of(submission) IN
                         /\ btc_canister_to_btc' = btc_canister_to_btc \ {submission}
                         /\ btc' = (new_utxos \union (btc \ submission.consumed_utxos))
                  /\ UNCHANGED nr_user_transfers
            /\ pc' = [pc EXCEPT ![BTC_PROCESS_ID] = "BTC_Loop"]
            /\ UNCHANGED << btc_canister, utxos_states_addresses, locks, 
                            pending, requests_sent, balance, 
                            minter_to_btc_canister, btc_canister_to_minter, 
                            minter_to_ledger, ledger_to_minter, 
                            next_request_id, resubmit_count, stack, submitted, 
                            spent, outputs, ck_btc_address, amount, 
                            resubmit_request_id, resubmission >>

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
                                                       THEN /\ btc_canister_to_btc' = (btc_canister_to_btc \union {req.submission})
                                                            /\ btc_canister_to_minter' = (btc_canister_to_minter \union {[ caller_id |-> (Caller(req)), status |-> Status_Ok ]})
                                                       ELSE /\ Assert((FALSE), 
                                                                      "Failure of assertion at line 483, column 29.")
                                                            /\ UNCHANGED << btc_canister_to_btc, 
                                                                            btc_canister_to_minter >>
                                   \/ /\ btc_canister_to_minter' = (btc_canister_to_minter \union { Error_Response((Caller(req))) })
                                      /\ UNCHANGED btc_canister_to_btc
                           /\ UNCHANGED btc_canister
                     /\ pc' = [pc EXCEPT ![BTC_CANISTER_PROCESS_ID] = "BTC_Canister_Loop"]
                     /\ UNCHANGED << btc, utxos_states_addresses, locks, 
                                     pending, requests_sent, balance, 
                                     minter_to_ledger, ledger_to_minter, 
                                     next_request_id, resubmit_count, stack, 
                                     submitted, spent, outputs, 
                                     nr_user_transfers, ck_btc_address, amount, 
                                     resubmit_request_id, resubmission >>

BTC_Canister == BTC_Canister_Loop

Ledger_Loop == /\ pc[LEDGER_PROCESS_ID] = "Ledger_Loop"
               /\ \/ /\ \E src_address \in DOMAIN balance \intersect CK_BTC_ADDRESSES:
                          \E dest_address \in CK_BTC_ADDRESSES
                                              \union
                                              { BTC_TO_WITHDRAWAL(x) :  x \in CK_BTC_ADDRESSES }:
                            \E amnt \in 1..balance[src_address]:
                              LET balance_with_default == balance @@ (dest_address :> 0) IN
                                balance' = Remove_Balance_If_Zero(src_address, [ balance_with_default EXCEPT ![src_address] = @ - amnt, ![dest_address] = @ + amnt ])
                     /\ UNCHANGED <<minter_to_ledger, ledger_to_minter>>
                  \/ /\ (minter_to_ledger # <<>>)
                     /\ LET req == Head(minter_to_ledger) IN
                          /\ minter_to_ledger' = Tail(minter_to_ledger)
                          /\ \/ /\ IF Is_Mint_Request(req)
                                      THEN /\ balance' = (       req.to :> (With_Default(balance, req.to, 0) + req.amount)
                                                          @@ balance)
                                           /\ ledger_to_minter' = (ledger_to_minter \union { [ caller_id |-> (req.caller_id), status |-> Status_Ok ] })
                                      ELSE /\ IF Is_Burn_Request(req)
                                                 THEN /\ IF req.address \in DOMAIN balance /\ balance[req.address] >= req.amount
                                                            THEN /\ balance' = Remove_Balance_If_Zero(req.address, [ balance EXCEPT ![req.address] = @ - req.amount])
                                                                 /\ ledger_to_minter' = (ledger_to_minter \union { [ caller_id |-> (Caller(req)), status |-> Status_Ok ] })
                                                            ELSE /\ ledger_to_minter' = (ledger_to_minter \union { [ caller_id |-> (Caller(req)), status |-> Status_Err ] })
                                                                 /\ UNCHANGED balance
                                                 ELSE /\ Assert((FALSE), 
                                                                "Failure of assertion at line 536, column 29.")
                                                      /\ UNCHANGED << balance, 
                                                                      ledger_to_minter >>
                             \/ /\ ledger_to_minter' = (ledger_to_minter \union { [ caller_id |-> (req.caller_id), status |-> Status_System_Err ] })
                                /\ UNCHANGED balance
               /\ pc' = [pc EXCEPT ![LEDGER_PROCESS_ID] = "Ledger_Loop"]
               /\ UNCHANGED << btc, btc_canister, utxos_states_addresses, 
                               locks, pending, requests_sent, 
                               btc_canister_to_btc, minter_to_btc_canister, 
                               btc_canister_to_minter, next_request_id, 
                               resubmit_count, stack, submitted, spent, 
                               outputs, nr_user_transfers, ck_btc_address, 
                               amount, resubmit_request_id, resubmission >>

Ledger == Ledger_Loop

Update_Balance_Start(self) == /\ pc[self] = "Update_Balance_Start"
                              /\ \E param_address \in CK_BTC_ADDRESSES:
                                   /\ (param_address \notin locks)
                                   /\ ck_btc_address' = [ck_btc_address EXCEPT ![self] = param_address]
                                   /\ locks' = (locks \union {ck_btc_address'[self]})
                                   /\ minter_to_btc_canister' =                       Append(minter_to_btc_canister,
                                                                Get_Utxos_Request(self, ck_btc_address'[self]))
                              /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Receive_Utxos"]
                              /\ UNCHANGED << btc, btc_canister, 
                                              utxos_states_addresses, pending, 
                                              requests_sent, balance, 
                                              btc_canister_to_btc, 
                                              btc_canister_to_minter, 
                                              minter_to_ledger, 
                                              ledger_to_minter, 
                                              next_request_id, resubmit_count, 
                                              stack, submitted, spent, outputs, 
                                              nr_user_transfers, amount, 
                                              resubmit_request_id, 
                                              resubmission >>

Update_Balance_Receive_Utxos(self) == /\ pc[self] = "Update_Balance_Receive_Utxos"
                                      /\ \E response \in { r \in btc_canister_to_minter: Caller(r) = self }:
                                           LET status == Status(response) IN
                                             /\ btc_canister_to_minter' = btc_canister_to_minter \ {response}
                                             /\ IF Is_Ok(status)
                                                   THEN /\ LET utxos == Get_Utxos_Result(response) IN
                                                             /\ Assert((Discovered_Utxos(utxos_states_addresses, ck_btc_address[self]) \subseteq utxos), 
                                                                       "Failure of assertion at line 574, column 13.")
                                                             /\ LET new_discovered ==              (utxos \ Processed_Utxos(utxos_states_addresses, ck_btc_address[self]))
                                                                                      \ Spent_Utxos(utxos_states_addresses, ck_btc_address[self]) IN
                                                                  LET new_spent == Spent_Utxos(utxos_states_addresses, ck_btc_address[self]) \intersect utxos IN
                                                                    utxos_states_addresses' = Set_Spent_Utxos(
                                                                                                  Set_Discovered_Utxos(utxos_states_addresses, ck_btc_address[self], new_discovered),
                                                                                              ck_btc_address[self],
                                                                                              new_spent)
                                                             /\ LET discovered_amount == Sum_Utxos(Discovered_Utxos(utxos_states_addresses', ck_btc_address[self])) IN
                                                                  IF discovered_amount > 0
                                                                     THEN /\ minter_to_ledger' = Append(minter_to_ledger, Mint_Request(self, ck_btc_address[self], discovered_amount))
                                                                          /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Mark_Minted"]
                                                                          /\ UNCHANGED << locks, 
                                                                                          ck_btc_address >>
                                                                     ELSE /\ locks' = locks \ {ck_btc_address[self]}
                                                                          /\ ck_btc_address' = [ck_btc_address EXCEPT ![self] = MINTER_BTC_ADDRESS]
                                                                          /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                                                          /\ UNCHANGED minter_to_ledger
                                                   ELSE /\ locks' = locks \ {ck_btc_address[self]}
                                                        /\ ck_btc_address' = [ck_btc_address EXCEPT ![self] = MINTER_BTC_ADDRESS]
                                                        /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                                        /\ UNCHANGED << utxos_states_addresses, 
                                                                        minter_to_ledger >>
                                      /\ UNCHANGED << btc, btc_canister, 
                                                      pending, requests_sent, 
                                                      balance, 
                                                      btc_canister_to_btc, 
                                                      minter_to_btc_canister, 
                                                      ledger_to_minter, 
                                                      next_request_id, 
                                                      resubmit_count, stack, 
                                                      submitted, spent, 
                                                      outputs, 
                                                      nr_user_transfers, 
                                                      amount, 
                                                      resubmit_request_id, 
                                                      resubmission >>

Update_Balance_Mark_Minted(self) == /\ pc[self] = "Update_Balance_Mark_Minted"
                                    /\ \E response \in { r \in ledger_to_minter: Caller(r) = self}:
                                         LET status == Status(response) IN
                                           LET processed == Processed_Utxos(utxos_states_addresses, ck_btc_address[self]) IN
                                             LET discovered == Discovered_Utxos(utxos_states_addresses, ck_btc_address[self]) IN
                                               /\ ledger_to_minter' = ledger_to_minter \ {response}
                                               /\ IF Is_Ok(status)
                                                     THEN /\ utxos_states_addresses' = Set_Discovered_Utxos(
                                                                                           Set_Processed_Utxos(utxos_states_addresses, ck_btc_address[self], processed \union discovered),
                                                                                           ck_btc_address[self],
                                                                                           {}
                                                                                       )
                                                     ELSE /\ TRUE
                                                          /\ UNCHANGED utxos_states_addresses
                                    /\ locks' = locks \ {ck_btc_address[self]}
                                    /\ ck_btc_address' = [ck_btc_address EXCEPT ![self] = MINTER_BTC_ADDRESS]
                                    /\ pc' = [pc EXCEPT ![self] = "Update_Balance_Start"]
                                    /\ UNCHANGED << btc, btc_canister, pending, 
                                                    requests_sent, balance, 
                                                    btc_canister_to_btc, 
                                                    minter_to_btc_canister, 
                                                    btc_canister_to_minter, 
                                                    minter_to_ledger, 
                                                    next_request_id, 
                                                    resubmit_count, stack, 
                                                    submitted, spent, outputs, 
                                                    nr_user_transfers, amount, 
                                                    resubmit_request_id, 
                                                    resubmission >>

Update_Balance(self) == Update_Balance_Start(self)
                           \/ Update_Balance_Receive_Utxos(self)
                           \/ Update_Balance_Mark_Minted(self)

Retrieve_BTC_Start(self) == /\ pc[self] = "Retrieve_BTC_Start"
                            /\ \E addr \in CK_BTC_ADDRESSES:
                                 \E amt \in 1..BTC_SUPPLY:
                                   /\ amount' = [amount EXCEPT ![self] = amt]
                                   /\ minter_to_ledger' = Append(minter_to_ledger, Burn_Request(self, (BTC_TO_WITHDRAWAL(addr)), amount'[self]))
                            /\ pc' = [pc EXCEPT ![self] = "Retrieve_BTC_Wait_Burn"]
                            /\ UNCHANGED << btc, btc_canister, 
                                            utxos_states_addresses, locks, 
                                            pending, requests_sent, balance, 
                                            btc_canister_to_btc, 
                                            minter_to_btc_canister, 
                                            btc_canister_to_minter, 
                                            ledger_to_minter, next_request_id, 
                                            resubmit_count, stack, submitted, 
                                            spent, outputs, nr_user_transfers, 
                                            ck_btc_address, 
                                            resubmit_request_id, resubmission >>

Retrieve_BTC_Wait_Burn(self) == /\ pc[self] = "Retrieve_BTC_Wait_Burn"
                                /\ \E response \in { r \in ledger_to_minter: Caller(r) = self }:
                                     LET status == Status(response) IN
                                       \E destination \in CK_BTC_ADDRESSES \union {                            USER_BTC_ADDRESS}:
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
                                                utxos_states_addresses, locks, 
                                                requests_sent, balance, 
                                                btc_canister_to_btc, 
                                                minter_to_btc_canister, 
                                                btc_canister_to_minter, 
                                                minter_to_ledger, 
                                                resubmit_count, stack, 
                                                submitted, spent, outputs, 
                                                nr_user_transfers, 
                                                ck_btc_address, 
                                                resubmit_request_id, 
                                                resubmission >>

Retrieve_BTC(self) == Retrieve_BTC_Start(self)
                         \/ Retrieve_BTC_Wait_Burn(self)

Start_Resubmit_Retrieve(self) == /\ pc[self] = "Start_Resubmit_Retrieve"
                                 /\ \E request_id \in DOMAIN requests_sent \union { req.request_id: req \in { pending[i]: i \in DOMAIN pending } }:
                                      IF request_id \in DOMAIN requests_sent
                                         THEN /\ LET new_submission == New_Submission(requests_sent[request_id].spent, requests_sent[request_id].outputs, resubmit_count) IN
                                                   /\ resubmit_count' = resubmit_count + 1
                                                   /\ resubmit_request_id' = [resubmit_request_id EXCEPT ![self] = request_id]
                                                   /\ resubmission' = [resubmission EXCEPT ![self] = new_submission]
                                                   /\ minter_to_btc_canister' =                       Append(minter_to_btc_canister,
                                                                                Submission_Request(self, new_submission))
                                              /\ pc' = [pc EXCEPT ![self] = "Conclude_Resubmission"]
                                         ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                                              /\ UNCHANGED << minter_to_btc_canister, 
                                                              resubmit_count, 
                                                              resubmit_request_id, 
                                                              resubmission >>
                                 /\ UNCHANGED << btc, btc_canister, 
                                                 utxos_states_addresses, locks, 
                                                 pending, requests_sent, 
                                                 balance, btc_canister_to_btc, 
                                                 btc_canister_to_minter, 
                                                 minter_to_ledger, 
                                                 ledger_to_minter, 
                                                 next_request_id, stack, 
                                                 submitted, spent, outputs, 
                                                 nr_user_transfers, 
                                                 ck_btc_address, amount >>

Conclude_Resubmission(self) == /\ pc[self] = "Conclude_Resubmission"
                               /\ \E response \in { r \in btc_canister_to_minter: Caller(r) = self }:
                                    LET status == Status(response) IN
                                      /\ btc_canister_to_minter' = btc_canister_to_minter \ {response}
                                      /\ IF Is_Ok(status)
                                            THEN /\ requests_sent' = (resubmit_request_id[self] :> resubmission[self] @@ requests_sent)
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED requests_sent
                                      /\ resubmit_request_id' = [resubmit_request_id EXCEPT ![self] = 0]
                                      /\ resubmission' = [resubmission EXCEPT ![self] = Empty_Fun]
                               /\ pc' = [pc EXCEPT ![self] = "Done"]
                               /\ UNCHANGED << btc, btc_canister, 
                                               utxos_states_addresses, locks, 
                                               pending, balance, 
                                               btc_canister_to_btc, 
                                               minter_to_btc_canister, 
                                               minter_to_ledger, 
                                               ledger_to_minter, 
                                               next_request_id, resubmit_count, 
                                               stack, submitted, spent, 
                                               outputs, nr_user_transfers, 
                                               ck_btc_address, amount >>

Resubmit_Retrieve_BTC(self) == Start_Resubmit_Retrieve(self)
                                  \/ Conclude_Resubmission(self)

Heartbeat_Start == /\ pc[HEARTBEAT_PROCESS_ID] = "Heartbeat_Start"
                   /\ (pending # <<>>)
                   /\ stack' = [stack EXCEPT ![HEARTBEAT_PROCESS_ID] = << [ procedure |->  "try_submit",
                                                                            pc        |->  "Heartbeat_Start",
                                                                            submitted |->  submitted[HEARTBEAT_PROCESS_ID],
                                                                            spent     |->  spent[HEARTBEAT_PROCESS_ID],
                                                                            outputs   |->  outputs[HEARTBEAT_PROCESS_ID] ] >>
                                                                        \o stack[HEARTBEAT_PROCESS_ID]]
                   /\ submitted' = [submitted EXCEPT ![HEARTBEAT_PROCESS_ID] = [request_id |-> 0, address |-> MINTER_BTC_ADDRESS, amount |-> 0]]
                   /\ spent' = [spent EXCEPT ![HEARTBEAT_PROCESS_ID] = {}]
                   /\ outputs' = [outputs EXCEPT ![HEARTBEAT_PROCESS_ID] = <<>>]
                   /\ pc' = [pc EXCEPT ![HEARTBEAT_PROCESS_ID] = "Get_Change_Utxos"]
                   /\ UNCHANGED << btc, btc_canister, utxos_states_addresses, 
                                   locks, pending, requests_sent, balance, 
                                   btc_canister_to_btc, minter_to_btc_canister, 
                                   btc_canister_to_minter, minter_to_ledger, 
                                   ledger_to_minter, next_request_id, 
                                   resubmit_count, nr_user_transfers, 
                                   ck_btc_address, amount, resubmit_request_id, 
                                   resubmission >>

Heartbeat == Heartbeat_Start

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == BTC \/ BTC_Canister \/ Ledger \/ Heartbeat
           \/ (\E self \in ProcSet: try_submit(self))
           \/ (\E self \in UPDATE_BALANCE_PROCESS_IDS: Update_Balance(self))
           \/ (\E self \in RETRIEVE_BTC_PROCESS_IDS: Retrieve_BTC(self))
           \/ (\E self \in RESUBMIT_RETRIEVE_BTC_PROCESS_IDS: Resubmit_Retrieve_BTC(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 

\**********************************************************************************************
\* Model sanity checks
\**********************************************************************************************
\* A bunch of properties we expect to be violated, as not violating them would mean
\* that our model can't do something we expect it to be able to do

Sanity_Inv_Cant_Deposit_To_Ck_BTC ==
    Utxos_Owned_By(btc, CK_BTC_ADDRESSES) = {}

Sanity_Inv_Cant_Mint_Ck_BTC == \A addr \in CK_BTC_ADDRESSES \intersect DOMAIN balance: 
    balance[addr] = 0

Sanity_Inv_Cant_Mint_To_Two_Addresses == ~(\E a1, a2 \in CK_BTC_ADDRESSES:
    /\ a1 # a2
    /\ a1 \in DOMAIN balance 
    /\ balance[a1] # 0
    /\ a2 \in DOMAIN balance 
    /\ balance[a2] # 0
    )

Sanity_Inv_Cant_Update_Two_Different_Addresses == \A p1, p2 \in UPDATE_BALANCE_PROCESS_IDS:
    /\ pc[p1] = "Done"
    /\ pc[p2] = "Done"
    => 
      ck_btc_address[p1] = ck_btc_address[p2]

Sanity_Inv_Cant_Have_Two_Deposits_To_Ck_BTC ==
    Cardinality(DOMAIN Utxos_Owned_By(btc, CK_BTC_ADDRESSES)) <= 1

Sanity_Inv_Cant_Deposit_To_Two_Ck_BTC_Addresses == ~(
    \E a1, a2 \in CK_BTC_ADDRESSES:
        /\ a1 # a2
        /\ Utxos_Owned_By(btc, {a1}) # {}
        /\ Utxos_Owned_By(btc, {a2}) # {}
)
Sanity_Inv_At_Most_One_Utxo == Cardinality(DOMAIN btc) <= 1

Sanity_Inv_Just_One_Message_To_Ledger == Len(minter_to_ledger) <= 1
Sanity_Inv_Just_One_Message_To_BTC_Canister == Len(minter_to_btc_canister) <= 1
Sanity_Inv_Just_One_Response_From_BTC_Canister == Cardinality(btc_canister_to_minter) <= 1

BTC_Balance_Of(addresses) == Sum_Utxos(Utxos_Owned_By(btc, addresses))

Sanity_No_Simultaneous_Minter_And_User_Owned_BTC == 
    BTC_Balance_Of({MINTER_BTC_ADDRESS}) # 0 <=> BTC_Balance_Of({USER_BTC_ADDRESS}) = 0

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
    Sum_F(LAMBDA x: balance[x], DOMAIN balance) <= BTC_Balance_Of(CK_BTC_ADDRESSES \union {MINTER_BTC_ADDRESS})

\* TODO: this is a newly added invariant, it hasn't been model checked yet
\* Any UTXOs that we mark as processed should at all times currently exist on the BTC network
Inv_Processed_Exist_On_The_BTC_Network ==
    All_Processed_Utxos(utxos_states_addresses) \subseteq btc

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

Inv_Requests_Either_Pending_Or_Sent == 
    DOMAIN requests_sent \intersect { p.request_id : p \in ToSet(pending) } = {}

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
    []<>(Sum_F(LAMBDA x: balance[x], DOMAIN balance) = BTC_Balance_Of(CK_BTC_ADDRESSES \union {MINTER_BTC_ADDRESS}))

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
                \A resp \in btc_canister_to_minter': Caller(resp) = req_pid => Is_Ok(Status(resp))
       )
    /\ \A addr \in CK_BTC_ADDRESSES \union {MINTER_BTC_ADDRESS}: SF_vars(
        /\ BTC_Canister_Loop 
        /\ minter_to_btc_canister # <<>> 
        /\ minter_to_btc_canister' # minter_to_btc_canister
        /\ Is_Get_Utxos_Request(Head(minter_to_btc_canister))
        /\ Get_Utxos_Request_Address(Head(minter_to_btc_canister)) = addr
        /\ LET req_pid == Caller(Head(minter_to_btc_canister)) IN
                \A resp \in btc_canister_to_minter': Caller(resp) = req_pid => Is_Ok(Status(resp))
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
            /\ ck_btc_address'[pid] = addr
        )
    \* Additionally, we want weak fairness for the remaining Update_Balance steps (they
    \* can't be ignored forever if they are enabled)
    /\ \A pid \in UPDATE_BALANCE_PROCESS_IDS: WF_vars(Update_Balance(pid))
    /\ \A pid \in RETRIEVE_BTC_PROCESS_IDS: WF_vars(Retrieve_BTC(pid))
    /\ \A pid \in RESUBMIT_RETRIEVE_BTC_PROCESS_IDS: WF_vars(Resubmit_Retrieve_BTC(pid))
    /\ WF_vars(Heartbeat)
    /\ WF_vars(try_submit(HEARTBEAT_PROCESS_ID))

\* To achieve the equality between ckBTC supply and the sum of UTXOs under the minter's control,
\* we have to assume that the users don't just transfer money to the ckBTC change address.
Prevent_External_Transfers_To_Change_Address ==
    \* Either this was not a user-initiated BTC transfer (because all of the previously 
    \* user-owned UTXOs are intact)...
    \/ Utxos_Owned_By(btc, {USER_BTC_ADDRESS}) \subseteq Utxos_Owned_By(btc', {USER_BTC_ADDRESS})
    \* ...or no new UTXOs were added to the change address
    \/ Utxos_Owned_By(btc', {MINTER_BTC_ADDRESS}) \subseteq Utxos_Owned_By(btc, {MINTER_BTC_ADDRESS})

Prevent_Retrievals_To_Change_Address ==
    \* The pid constraints determine the moment when the model decides on the destination of
    \* a BTC retrieval...
    \A pid \in RETRIEVE_BTC_PROCESS_IDS:
            /\ pc[pid] = "Retrieve_BTC_Wait_Burn"
            /\ pc'[pid] = "Done"
            /\ pending' # pending
        =>
            \* ...and we require that the destination is not the change address
            Head(pending').address # MINTER_BTC_ADDRESS
 
 Prevent_Donations_To_Change_Address ==
    /\ Prevent_External_Transfers_To_Change_Address
    /\ Prevent_Retrievals_To_Change_Address


Liveness_Spec ==
    /\ Init
    /\ [][Next /\ Prevent_Donations_To_Change_Address]_vars
    /\ Fairness_Condition
 
====
