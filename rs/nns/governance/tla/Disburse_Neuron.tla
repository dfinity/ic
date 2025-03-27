---- MODULE Disburse_Neuron ----

EXTENDS TLC, Integers, FiniteSets, Sequences, Variants, Common

CONSTANTS
    Governance_Account_Ids,
    Account_Ids,
    Minting_Account_Id

CONSTANTS
    Disburse_Neuron_Process_Ids

CONSTANTS
    \* Minimum stake a neuron can have
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    TRANSACTION_FEE

CONSTANT
    \* Which argument to give as an amount; for Apalache, we can take Nat,
    \* for TLC we want to limit this to some finite set
    POSSIBLE_DISBURSE_AMOUNTS(_, _)

Max(x, y) == IF x < y THEN y ELSE x

(* --algorithm Governance_Ledger_Disburse_Neuron {

variables

    neuron \in [{} -> {}];
    \* Used to decide whether we should refresh or claim a neuron
    neuron_id_by_account \in [{} -> {}];
    \* The set of currently locked neurons
    locks = {};
    \* The queue of messages sent from the governance canister to the ledger canister
    governance_to_ledger = <<>>;
    ledger_to_governance = {};
    spawning_neurons = FALSE;

macro send_request(caller_id, request_args) {
    governance_to_ledger := Append(governance_to_ledger, request(caller_id, request_args))
};

macro update_fees(neuron_id, fees_amount) {
    if(neuron[neuron_id].cached_stake > fees_amount) {
        neuron := [neuron EXCEPT ![neuron_id] = [@ EXCEPT !.cached_stake = @ - fees_amount, !.fees = 0]]
    } else {
        neuron := [neuron EXCEPT ![neuron_id] = [@ EXCEPT !.cached_stake = 0, !.fees = 0]];
    };
}

macro finish() {
    locks := locks \ {neuron_id};
    neuron_id := 0;
    disburse_amount := 0;
    to_account := DUMMY_ACCOUNT;
    fees_amount := 0;
    goto Done;
}

process ( Disburse_Neuron \in Disburse_Neuron_Process_Ids )
    variable
        \* These model the parameters of the call
        neuron_id = 0;
        disburse_amount = 0;
        to_account = DUMMY_ACCOUNT;
        \* The model the internal variables of the procedure.
        \* Since +Cal doesn't allow multiple assignments to the same variable in a single block,
        \* we also use temporary variables to simulate this and stay closer to the source code
        fees_amount = 0;
    {
    DisburseNeuron1:
        either {
            \* Simulate calls that just fail early and don't change the state.
            \* Not so useful for model checking, but needed to follow the code traces.
            goto Done;
        } or {
            \* This models a few checks at the start of the Rust code.
            \* We currently omit the check that the neuron is dissolved, and we plan to add this later.
            \* We omit the other checks: who the caller is, whether the neuron is KYC verified, as well
            \* as a few well-formedness checks (of the neuron and recipient account) as everything in
            \* our model is well-formed.
            \* Note that the user can request to disburse an arbitrary amount. This will only fail once
            \* we send a message to the ledger.
            with(nid \in DOMAIN(neuron) \ locks; amt \in POSSIBLE_DISBURSE_AMOUNTS(neuron, nid); account \in Account_Ids) {
                neuron_id := nid;
                disburse_amount := amt;
                fees_amount := neuron[neuron_id].fees;
                to_account := account;
                \* The Rust code has a more elaborate code path to determine the disburse_amount, where the
                \* amount argument is left unspecified in the call, and a default value is computed instead.
                \* As this default value is in the range between 0 and the neuron's cached_stake, our
                \* non-deterministic choice should cover this case.
                \* The Rust code throws an error here if the neuron is locked. Instead, we prevent the Disburse_Neuron process from running.
                \* This is OK since the Rust code doesn't change the canister's state before obtaining the lock (if it
                \* did, the model wouldn't capture this and we could miss behaviors).
                locks := locks \union {neuron_id};
                if(fees_amount > TRANSACTION_FEE) {
                    send_request(self, transfer(neuron[neuron_id].account, Minting_Account_Id, fees_amount, 0));
                }
                else {
                    update_fees(neuron_id, fees_amount);
                    send_request(self, transfer(neuron[neuron_id].account, to_account, disburse_amount, TRANSACTION_FEE));
                    goto DisburseNeuron_Stake_WaitForTransfer;
                };
            };
         };
    DisburseNeuron_Fee_WaitForTransfer:
        \* Note that we're here only because the fees amount was larger than the
        \* transaction fee (otherwise, the goto above would have taken us to DisburseNeuron3)
        with(answer \in { resp \in ledger_to_governance: resp.caller = self}) {
            ledger_to_governance := ledger_to_governance \ {answer};
            if(answer.response = Variant("Fail", UNIT)) {
                finish();
            } else {
                update_fees(neuron_id, fees_amount);
                send_request(self, transfer(neuron[neuron_id].account, to_account, disburse_amount, TRANSACTION_FEE));
            };
        };

    DisburseNeuron_Stake_WaitForTransfer:
        with(answer \in { resp \in ledger_to_governance: resp.caller = self}) {
            ledger_to_governance := ledger_to_governance \ {answer};
            if(answer.response # Variant("Fail", UNIT)) {
               neuron := [neuron EXCEPT![neuron_id].cached_stake =
                    Max(0, @ - (disburse_amount + TRANSACTION_FEE))];
            };
        };
        finish();
    }
}
*)
\* BEGIN TRANSLATION (chksum(pcal) = "10c9c7f7" /\ chksum(tla) = "a1672e89")
VARIABLES pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
          ledger_to_governance, spawning_neurons, neuron_id, disburse_amount,
          to_account, fees_amount

vars == << pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
           ledger_to_governance, spawning_neurons, neuron_id, disburse_amount,
           to_account, fees_amount >>

ProcSet == (Disburse_Neuron_Process_Ids)

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}
        /\ spawning_neurons = FALSE
        (* Process Disburse_Neuron *)
        /\ neuron_id = [self \in Disburse_Neuron_Process_Ids |-> 0]
        /\ disburse_amount = [self \in Disburse_Neuron_Process_Ids |-> 0]
        /\ to_account = [self \in Disburse_Neuron_Process_Ids |-> DUMMY_ACCOUNT]
        /\ fees_amount = [self \in Disburse_Neuron_Process_Ids |-> 0]
        /\ pc = [self \in ProcSet |-> "DisburseNeuron1"]

DisburseNeuron1(self) == /\ pc[self] = "DisburseNeuron1"
                         /\ \/ /\ pc' = [pc EXCEPT ![self] = "Done"]
                               /\ UNCHANGED <<neuron, locks, governance_to_ledger, neuron_id, disburse_amount, to_account, fees_amount>>
                            \/ /\ \E nid \in DOMAIN(neuron) \ locks:
                                    \E amt \in POSSIBLE_DISBURSE_AMOUNTS(neuron, nid):
                                      \E account \in Account_Ids:
                                        /\ neuron_id' = [neuron_id EXCEPT ![self] = nid]
                                        /\ disburse_amount' = [disburse_amount EXCEPT ![self] = amt]
                                        /\ fees_amount' = [fees_amount EXCEPT ![self] = neuron[neuron_id'[self]].fees]
                                        /\ to_account' = [to_account EXCEPT ![self] = account]
                                        /\ locks' = (locks \union {neuron_id'[self]})
                                        /\ IF fees_amount'[self] > TRANSACTION_FEE
                                              THEN /\ governance_to_ledger' = Append(governance_to_ledger, request(self, (transfer(neuron[neuron_id'[self]].account, Minting_Account_Id, fees_amount'[self], 0))))
                                                   /\ pc' = [pc EXCEPT ![self] = "DisburseNeuron_Fee_WaitForTransfer"]
                                                   /\ UNCHANGED neuron
                                              ELSE /\ IF neuron[neuron_id'[self]].cached_stake > fees_amount'[self]
                                                         THEN /\ neuron' = [neuron EXCEPT ![neuron_id'[self]] = [@ EXCEPT !.cached_stake = @ - fees_amount'[self], !.fees = 0]]
                                                         ELSE /\ neuron' = [neuron EXCEPT ![neuron_id'[self]] = [@ EXCEPT !.cached_stake = 0, !.fees = 0]]
                                                   /\ governance_to_ledger' = Append(governance_to_ledger, request(self, (transfer(neuron'[neuron_id'[self]].account, to_account'[self], disburse_amount'[self], TRANSACTION_FEE))))
                                                   /\ pc' = [pc EXCEPT ![self] = "DisburseNeuron_Stake_WaitForTransfer"]
                         /\ UNCHANGED << neuron_id_by_account,
                                         ledger_to_governance,
                                         spawning_neurons >>

DisburseNeuron_Fee_WaitForTransfer(self) == /\ pc[self] = "DisburseNeuron_Fee_WaitForTransfer"
                                            /\ \E answer \in { resp \in ledger_to_governance: resp.caller = self}:
                                                 /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                                 /\ IF answer.response = Variant("Fail", UNIT)
                                                       THEN /\ locks' = locks \ {neuron_id[self]}
                                                            /\ neuron_id' = [neuron_id EXCEPT ![self] = 0]
                                                            /\ disburse_amount' = [disburse_amount EXCEPT ![self] = 0]
                                                            /\ to_account' = [to_account EXCEPT ![self] = DUMMY_ACCOUNT]
                                                            /\ fees_amount' = [fees_amount EXCEPT ![self] = 0]
                                                            /\ pc' = [pc EXCEPT ![self] = "Done"]
                                                            /\ UNCHANGED << neuron,
                                                                            governance_to_ledger >>
                                                       ELSE /\ IF neuron[neuron_id[self]].cached_stake > fees_amount[self]
                                                                  THEN /\ neuron' = [neuron EXCEPT ![neuron_id[self]] = [@ EXCEPT !.cached_stake = @ - fees_amount[self], !.fees = 0]]
                                                                  ELSE /\ neuron' = [neuron EXCEPT ![neuron_id[self]] = [@ EXCEPT !.cached_stake = 0, !.fees = 0]]
                                                            /\ governance_to_ledger' = Append(governance_to_ledger, request(self, (transfer(neuron'[neuron_id[self]].account, to_account[self], disburse_amount[self], TRANSACTION_FEE))))
                                                            /\ pc' = [pc EXCEPT ![self] = "DisburseNeuron_Stake_WaitForTransfer"]
                                                            /\ UNCHANGED << locks,
                                                                            neuron_id,
                                                                            disburse_amount,
                                                                            to_account,
                                                                            fees_amount >>
                                            /\ UNCHANGED << neuron_id_by_account,
                                                            spawning_neurons >>

DisburseNeuron_Stake_WaitForTransfer(self) == /\ pc[self] = "DisburseNeuron_Stake_WaitForTransfer"
                                              /\ \E answer \in { resp \in ledger_to_governance: resp.caller = self}:
                                                   /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                                   /\ IF answer.response # Variant("Fail", UNIT)
                                                         THEN /\ neuron' =      [neuron EXCEPT![neuron_id[self]].cached_stake =
                                                                           Max(0, @ - (disburse_amount[self] + TRANSACTION_FEE))]
                                                         ELSE /\ TRUE
                                                              /\ UNCHANGED neuron
                                              /\ locks' = locks \ {neuron_id[self]}
                                              /\ neuron_id' = [neuron_id EXCEPT ![self] = 0]
                                              /\ disburse_amount' = [disburse_amount EXCEPT ![self] = 0]
                                              /\ to_account' = [to_account EXCEPT ![self] = DUMMY_ACCOUNT]
                                              /\ fees_amount' = [fees_amount EXCEPT ![self] = 0]
                                              /\ pc' = [pc EXCEPT ![self] = "Done"]
                                              /\ UNCHANGED << neuron_id_by_account,
                                                              governance_to_ledger,
                                                              spawning_neurons >>

Disburse_Neuron(self) == DisburseNeuron1(self)
                            \/ DisburseNeuron_Fee_WaitForTransfer(self)
                            \/ DisburseNeuron_Stake_WaitForTransfer(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in Disburse_Neuron_Process_Ids: Disburse_Neuron(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

====
