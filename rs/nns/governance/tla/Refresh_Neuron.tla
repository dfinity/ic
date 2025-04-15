------------ MODULE Refresh_Neuron ------------
EXTENDS TLC, Sequences, Naturals, FiniteSets, Variants, Common

CONSTANTS
    Governance_Account_Ids

CONSTANTS
    Refresh_Neuron_Process_Ids

CONSTANTS
    \* Minimum stake a neuron can have
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    TRANSACTION_FEE

(* --algorithm Governance_Ledger_Refresh_Neuron {

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

macro refresh_neuron_reset_local_vars() {
    neuron_id := 0;
}


\* Modified from formal-models/tla/governance-ledger
\* A Refresh_Neuron process simulates a call to refresh_neuron
process ( Refresh_Neuron \in Refresh_Neuron_Process_Ids )
    variable
        \* There are two ways that the user can invoke a neuron refresh:
        \* 1. by specifying an account ID
        \* 2. by specifying an existing neuron ID
        \* We only model the second option; the second should follow from the invariant that
        \* \A nid aid : neuron_id_by_account[aid] = nid <=> neuron[nid].account = aid

        \* The neuron_id is an argument; we let it be chosen non-deteministically
        neuron_id = 0;
    {
    RefreshNeuron1:
        either {
            \* Simulate calls that just fail early and don't change the state.
            \* Not so useful for model checking, but needed to follow the code traces.
            goto Done;
        } or {
        with(nid \in DOMAIN(neuron) \ locks) {
            neuron_id := nid;
            locks := locks \union {neuron_id};
            governance_to_ledger := Append(governance_to_ledger, request(self, account_balance(neuron[nid].account)));
        };
        };
    WaitForBalanceQuery:
        \* Note that the "with" construct implicitly awaits until the set of values to draw from is non-empty
        with(answer \in { resp \in ledger_to_governance : resp.caller = self }) {
            ledger_to_governance := ledger_to_governance \ {answer};
            if(answer.response /= Variant("Fail", UNIT)) {
                with (b = VariantGetOrElse("BalanceQueryOk", answer.response, 0)) {
                    if(b >= MIN_STAKE) {
                        neuron := [neuron EXCEPT ![neuron_id].cached_stake = b ]
                    };
                };
            };
            locks := locks \ {neuron_id};
        };
        refresh_neuron_reset_local_vars();
    };

}
*)
\* BEGIN TRANSLATION (chksum(pcal) = "e3951dde" /\ chksum(tla) = "d922bb3e")
VARIABLES pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
          ledger_to_governance, spawning_neurons, neuron_id

vars == << pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
           ledger_to_governance, spawning_neurons, neuron_id >>

ProcSet == (Refresh_Neuron_Process_Ids)

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}
        /\ spawning_neurons = FALSE
        (* Process Refresh_Neuron *)
        /\ neuron_id = [self \in Refresh_Neuron_Process_Ids |-> 0]
        /\ pc = [self \in ProcSet |-> "RefreshNeuron1"]

RefreshNeuron1(self) == /\ pc[self] = "RefreshNeuron1"
                        /\ \/ /\ pc' = [pc EXCEPT ![self] = "Done"]
                              /\ UNCHANGED <<locks, governance_to_ledger, neuron_id>>
                           \/ /\ \E nid \in DOMAIN(neuron) \ locks:
                                   /\ neuron_id' = [neuron_id EXCEPT ![self] = nid]
                                   /\ locks' = (locks \union {neuron_id'[self]})
                                   /\ governance_to_ledger' = Append(governance_to_ledger, request(self, account_balance(neuron[nid].account)))
                              /\ pc' = [pc EXCEPT ![self] = "WaitForBalanceQuery"]
                        /\ UNCHANGED << neuron, neuron_id_by_account,
                                        ledger_to_governance, spawning_neurons >>

WaitForBalanceQuery(self) == /\ pc[self] = "WaitForBalanceQuery"
                             /\ \E answer \in { resp \in ledger_to_governance : resp.caller = self }:
                                  /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                  /\ IF answer.response /= Variant("Fail", UNIT)
                                        THEN /\ LET b == VariantGetOrElse("BalanceQueryOk", answer.response, 0) IN
                                                  IF b >= MIN_STAKE
                                                     THEN /\ neuron' = [neuron EXCEPT ![neuron_id[self]].cached_stake = b ]
                                                     ELSE /\ TRUE
                                                          /\ UNCHANGED neuron
                                        ELSE /\ TRUE
                                             /\ UNCHANGED neuron
                                  /\ locks' = locks \ {neuron_id[self]}
                             /\ neuron_id' = [neuron_id EXCEPT ![self] = 0]
                             /\ pc' = [pc EXCEPT ![self] = "Done"]
                             /\ UNCHANGED << neuron_id_by_account,
                                             governance_to_ledger,
                                             spawning_neurons >>

Refresh_Neuron(self) == RefreshNeuron1(self) \/ WaitForBalanceQuery(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in Refresh_Neuron_Process_Ids: Refresh_Neuron(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

====
