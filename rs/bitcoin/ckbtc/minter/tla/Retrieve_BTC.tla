---- MODULE Retrieve_BTC ----
EXTENDS TLC, Sequences, Integers, FiniteSets, FiniteSetsExt, SequencesExt, Functions, Variants, Apalache, TLA_Hash, TypeAliases, Ckbtc_Common

CONSTANTS
    \* The set of process IDs for Retrieve_BTC process.
    \* This roughly, corresponding to the set of call contexts for the retrieve_btc method,
    \* and limits the number of times that retrieve_btc can be called.
    RETRIEVE_BTC_PROCESS_IDS,
    \**********************************************************************************************
    \* Other constants
    \**********************************************************************************************
    \* The "user-controlled" BTC address; we assume just one such address in this model.
    USER_BTC_ADDRESS,
    BTC_SUPPLY,
    RETRIEVE_BTC_FEE,
    DEPOSIT_ADDRESS

\* Put a submission at the end of the minter's "pending" queue
\* @type: (Seq($withdrawalReq), $requestId, $btcAddress, $amount) => Seq($withdrawalReq);
Queue_Pending(pending, request_id, address, amount) == Append(pending,
    [ request_id |-> request_id, address |-> address, amount |-> amount ])

(* --algorithm retrieve_btc {

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

    minter_to_btc_canister = <<>>;
    btc_canister_to_minter = {};
    minter_to_ledger = <<>>;
    ledger_to_minter = {};
    next_request_id = 1;

macro send_minter_to_ledger_burn(caller_id, address, amount) {
    minter_to_ledger := Append(minter_to_ledger, Burn_Request(caller_id, address, amount));
}

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

}
*)
\* BEGIN TRANSLATION (chksum(pcal) = "4489f86e" /\ chksum(tla) = "16e589a0")
VARIABLES pc, utxos_state_addresses, available_utxos, finalized_utxos, locks, 
          pending, submitted_transactions, minter_to_btc_canister, 
          btc_canister_to_minter, minter_to_ledger, ledger_to_minter, 
          next_request_id, amount

vars == << pc, utxos_state_addresses, available_utxos, finalized_utxos, locks, 
           pending, submitted_transactions, minter_to_btc_canister, 
           btc_canister_to_minter, minter_to_ledger, ledger_to_minter, 
           next_request_id, amount >>

ProcSet == (RETRIEVE_BTC_PROCESS_IDS)

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
        /\ next_request_id = 1
        (* Process Retrieve_BTC *)
        /\ amount = [self \in RETRIEVE_BTC_PROCESS_IDS |-> 0]
        /\ pc = [self \in ProcSet |-> "Retrieve_BTC_Start"]

Retrieve_BTC_Start(self) == /\ pc[self] = "Retrieve_BTC_Start"
                            /\ \E user \in PRINCIPALS:
                                 \E amt \in 1..BTC_SUPPLY:
                                   /\ amount' = [amount EXCEPT ![self] = amt]
                                   /\ minter_to_ledger' = Append(minter_to_ledger, Burn_Request(self, (BURN_ADDRESS(user)), amount'[self]))
                            /\ pc' = [pc EXCEPT ![self] = "Retrieve_BTC_Wait_Burn"]
                            /\ UNCHANGED << utxos_state_addresses, 
                                            available_utxos, finalized_utxos, 
                                            locks, pending, 
                                            submitted_transactions, 
                                            minter_to_btc_canister, 
                                            btc_canister_to_minter, 
                                            ledger_to_minter, next_request_id >>

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
                                /\ UNCHANGED << utxos_state_addresses, 
                                                available_utxos, 
                                                finalized_utxos, locks, 
                                                submitted_transactions, 
                                                minter_to_btc_canister, 
                                                btc_canister_to_minter, 
                                                minter_to_ledger >>

Retrieve_BTC(self) == Retrieve_BTC_Start(self)
                         \/ Retrieve_BTC_Wait_Burn(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in RETRIEVE_BTC_PROCESS_IDS: Retrieve_BTC(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 

local_vars == << amount, next_request_id  >>

Local_Init ==
    /\ amount = [self \in RETRIEVE_BTC_PROCESS_IDS |-> 0]

====
