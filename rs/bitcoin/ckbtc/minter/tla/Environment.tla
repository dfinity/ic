---- MODULE Environment ----
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
    DEPOSIT_ADDRESS

\* @type: $submission => Set($utxo);
Utxos_Of(submission) ==
    LET
        tx_hash == Tx_Hash(submission)
    IN
        { [id |-> << tx_hash, i >>, owner |-> submission.outputs[i].owner, value |-> submission.outputs[i].value] 
            : i \in 1..Len(submission.outputs) }

BTC_Canister_Error_Response(caller_id) == [ caller_id |-> caller_id, response |-> Variant("Error", UNIT) ]


\* Remove a key from the balance map (i.e., undefine the partial function for that key) if its value is 0.
Remove_Balance_If_Zero(addr, b) == IF addr \in DOMAIN b /\ b[addr] = 0 THEN Remove_Argument(b, addr) ELSE b



(*--algorithm environment {

variables
    \**********************************************************************************************
    \* BTC Network
    \**********************************************************************************************
    \* The "current state" of the BTC network, as just a set of UTXOs. Of course, this
    \* is a simplification, as the BTC network doesn't have a notion of current state.
    \* We don't attempt to define a precise mapping onto the state of the BTC network here.
    btc = { 
        [ id |-> << "GENESIS", 0 >>, owner |-> USER_BTC_ADDRESS, value |-> BTC_SUPPLY - MINTER_INITIAL_SUPPLY], 
        [ id |-> << "GENESIS", 1 >>, owner |-> DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS], value |-> MINTER_INITIAL_SUPPLY] };
    \**********************************************************************************************
    \* BTC Canister
    \**********************************************************************************************
    \* The state of the BTC canister, also as just a set of UTXOs. It's a
    \* snapshot of the BTC network state at some point in time.
    btc_canister = {};
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

macro respond_ledger_to_minter(caller_id, status) {
    ledger_to_minter := ledger_to_minter \union { [ caller_id |-> caller_id, status |-> status ] }
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
                    transaction = [ consumed_utxos |-> user_utxos, outputs |-> New_Outputs(user_utxos, <<[address |-> dest_address, value |-> dest_amount]>>, USER_BTC_ADDRESS) ];
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

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "74e2ab5f" /\ chksum(tla) = "e3698aa0")
VARIABLES btc, btc_canister, balance, btc_canister_to_btc, 
          minter_to_btc_canister, btc_canister_to_minter, minter_to_ledger, 
          ledger_to_minter, nr_user_transfers

vars == << btc, btc_canister, balance, btc_canister_to_btc, 
           minter_to_btc_canister, btc_canister_to_minter, minter_to_ledger, 
           ledger_to_minter, nr_user_transfers >>

ProcSet == {BTC_PROCESS_ID} \cup {BTC_CANISTER_PROCESS_ID} \cup {LEDGER_PROCESS_ID}

Init == (* Global variables *)
        /\ btc =   {
                 [ id |-> << "GENESIS", 0 >>, owner |-> USER_BTC_ADDRESS, value |-> BTC_SUPPLY - MINTER_INITIAL_SUPPLY],
                 [ id |-> << "GENESIS", 1 >>, owner |-> DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS], value |-> MINTER_INITIAL_SUPPLY] }
        /\ btc_canister = {}
        /\ balance \in Empty_Funs
        /\ btc_canister_to_btc = {}
        /\ minter_to_btc_canister = <<>>
        /\ btc_canister_to_minter = {}
        /\ minter_to_ledger = <<>>
        /\ ledger_to_minter = {}
        (* Process BTC *)
        /\ nr_user_transfers = 0

BTC == /\ \/ /\ (nr_user_transfers < MAX_USER_BTC_TRANSFERS)
             /\ \E user_utxos \in SUBSET Utxos_Owned_By(btc, {USER_BTC_ADDRESS}):
                  \E dest_address \in Image(DEPOSIT_ADDRESS, CK_BTC_ADDRESSES \union {MINTER_CKBTC_ADDRESS}):
                    \E dest_amount \in 1..Sum_Utxos(user_utxos):
                      LET transaction == [ consumed_utxos |-> user_utxos, outputs |-> New_Outputs(user_utxos, <<[address |-> dest_address, value |-> dest_amount]>>, USER_BTC_ADDRESS) ] IN
                        LET local_new_utxos == Utxos_Of(transaction) IN
                          /\ btc' = ((btc \ user_utxos) \union local_new_utxos)
                          /\ nr_user_transfers' = nr_user_transfers + 1
             /\ UNCHANGED btc_canister_to_btc
          \/ /\ \E submission \in { s \in btc_canister_to_btc: s.consumed_utxos \subseteq btc }:
                  LET local_new_utxos == Utxos_Of(submission) IN
                    /\ btc_canister_to_btc' = btc_canister_to_btc \ {submission}
                    /\ btc' = (local_new_utxos \union (btc \ submission.consumed_utxos))
             /\ UNCHANGED nr_user_transfers
       /\ UNCHANGED << btc_canister, balance, minter_to_btc_canister, 
                       btc_canister_to_minter, minter_to_ledger, 
                       ledger_to_minter >>

BTC_Canister == /\ \/ /\ btc_canister' = btc
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
                                                                 "Failure of assertion at line 180, column 13.")
                                                       /\ UNCHANGED << btc_canister_to_btc, 
                                                                       btc_canister_to_minter >>
                              \/ /\ btc_canister_to_minter' = (btc_canister_to_minter \union { BTC_Canister_Error_Response((Caller(req))) })
                                 /\ UNCHANGED btc_canister_to_btc
                      /\ UNCHANGED btc_canister
                /\ UNCHANGED << btc, balance, minter_to_ledger, 
                                ledger_to_minter, nr_user_transfers >>

Ledger == /\ \/ /\ \E src_address \in DOMAIN balance \intersect CK_BTC_ADDRESSES:
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
                                                           "Failure of assertion at line 237, column 29.")
                                                 /\ UNCHANGED << balance, 
                                                                 ledger_to_minter >>
                        \/ /\ ledger_to_minter' = (ledger_to_minter \union { [ caller_id |-> (req.caller_id), status |-> Status_System_Err ] })
                           /\ UNCHANGED balance
          /\ UNCHANGED << btc, btc_canister, btc_canister_to_btc, 
                          minter_to_btc_canister, btc_canister_to_minter, 
                          nr_user_transfers >>

Next == BTC \/ BTC_Canister \/ Ledger

Spec == Init /\ [][Next]_vars

\* END TRANSLATION 

local_vars == << btc, btc_canister, balance, nr_user_transfers, btc_canister_to_btc >>

Local_Init ==
    /\ btc =   {
             [ id |-> << "GENESIS", 0 >>, owner |-> USER_BTC_ADDRESS, value |-> BTC_SUPPLY - MINTER_INITIAL_SUPPLY],
             [ id |-> << "GENESIS", 1 >>, owner |-> DEPOSIT_ADDRESS[MINTER_CKBTC_ADDRESS], value |-> MINTER_INITIAL_SUPPLY] }
    /\ btc_canister = {}
    (* Process BTC *)
    /\ nr_user_transfers = 0


====
