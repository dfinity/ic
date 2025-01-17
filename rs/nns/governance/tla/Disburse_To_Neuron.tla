---- MODULE Disburse_To_Neuron ----

EXTENDS TLC, Integers, FiniteSets, Sequences, Variants

CONSTANTS
    Governance_Account_Ids,
    Neuron_Ids

CONSTANTS
    Disburse_To_Neuron_Process_Ids

CONSTANTS
    \* Minimum stake a neuron can have
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    TRANSACTION_FEE

CONSTANT
    FRESH_NEURON_ID(_)

\* Initial value used for uninitialized accounts
DUMMY_ACCOUNT == ""

\* @type: (a -> b, Set(a)) => a -> b;
Remove_Arguments(f, S) == [ x \in (DOMAIN f \ S) |-> f[x]]
Max(x, y) == IF x < y THEN y ELSE x

request(caller, request_args) == [caller |-> caller, method_and_args |-> request_args]
transfer(from, to, amount, fee) == Variant("Transfer", [from |-> from, to |-> to, amount |-> amount, fee |-> fee])

o_deduct(disb_amount) == disb_amount + TRANSACTION_FEE

(* --algorithm Governance_Ledger_Disburse_To_Neuron {

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

process (Disburse_To_Neuron \in Disburse_To_Neuron_Process_Ids)
    variables
        parent_neuron_id = 0;
        disburse_amount = 0;
        child_account_id = DUMMY_ACCOUNT;
        child_neuron_id = 0;
    {
    DisburseToNeuron:
        either {
            \* Simulate calls that just fail early and don't change the state.
            \* Not so useful for model checking, but needed to follow the code traces.
            goto Done;
        } or {
            \* Skipping a few checks again:
            \* 1. authorization of the caller
            \* 2. that the parent neuron has been dissolved
            \* 3. kyc checks
            \* 4. checks on the presence and shape of new controller
            with(pnid \in DOMAIN(neuron) \ locks;
                    parent_neuron = neuron[pnid];
                    amt \in (MIN_STAKE + TRANSACTION_FEE)..(parent_neuron.cached_stake - parent_neuron.fees - MIN_STAKE);
                    c_acc_id \in Governance_Account_Ids \ { neuron[n].account : n \in DOMAIN(neuron)};
                ) {
                parent_neuron_id := pnid;
                disburse_amount := amt;
                await parent_neuron.maturity <= TRANSACTION_FEE;
                child_account_id := c_acc_id;
                child_neuron_id := FRESH_NEURON_ID(DOMAIN(neuron));
                neuron_id_by_account := child_account_id :> child_neuron_id @@ neuron_id_by_account;
                neuron := child_neuron_id :> [ cached_stake |-> 0, account |-> child_account_id, fees |-> 0, maturity |-> 0 ] @@ neuron;
                \* The Rust code throws an error here if the parent neuron is locked. Instead, we prevent the Disburse_To_Neuron process from running.
                \* This is OK since the Rust code doesn't change the canister's state before obtaining the parant lock (if it
                \* did, the model wouldn't capture this state and we could miss behaviors).
                assert child_neuron_id \notin locks;
                \* Note that in the implementation this implies that child_neuron_id != parent_neuron_id,
                \* as the locks are taken sequentially there; here, we're sure that these neuron IDs differ,
                \* so we omit the extra check.
                locks := locks \union {parent_neuron_id, child_neuron_id};
                send_request(self, transfer(parent_neuron.account, child_account_id, disburse_amount - TRANSACTION_FEE, TRANSACTION_FEE));
            };
        };
    DisburseToNeuron_WaitForTransfer:
        with(answer \in { resp \in ledger_to_governance: resp.caller = self}) {
                ledger_to_governance := ledger_to_governance \ {answer};
                if(answer.response = Variant("Fail", UNIT)) {
                    neuron := Remove_Arguments(neuron, {child_neuron_id});
                    neuron_id_by_account := Remove_Arguments(neuron_id_by_account, {child_account_id});
                } else {
                    neuron := [ neuron EXCEPT ![parent_neuron_id].cached_stake = @ - disburse_amount,
                        ![child_neuron_id].cached_stake = disburse_amount - TRANSACTION_FEE ];
                };
                locks := locks \ {parent_neuron_id, child_neuron_id};
                parent_neuron_id := 0;
                disburse_amount := 0;
                child_account_id := DUMMY_ACCOUNT;
                child_neuron_id := 0;
        };

    }
}
*)
\* BEGIN TRANSLATION (chksum(pcal) = "d03e80ed" /\ chksum(tla) = "b79d8d63")
VARIABLES pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
          ledger_to_governance, spawning_neurons, parent_neuron_id,
          disburse_amount, child_account_id, child_neuron_id

vars == << pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
           ledger_to_governance, spawning_neurons, parent_neuron_id,
           disburse_amount, child_account_id, child_neuron_id >>

ProcSet == (Disburse_To_Neuron_Process_Ids)

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}
        /\ spawning_neurons = FALSE
        (* Process Disburse_To_Neuron *)
        /\ parent_neuron_id = [self \in Disburse_To_Neuron_Process_Ids |-> 0]
        /\ disburse_amount = [self \in Disburse_To_Neuron_Process_Ids |-> 0]
        /\ child_account_id = [self \in Disburse_To_Neuron_Process_Ids |-> DUMMY_ACCOUNT]
        /\ child_neuron_id = [self \in Disburse_To_Neuron_Process_Ids |-> 0]
        /\ pc = [self \in ProcSet |-> "DisburseToNeuron"]

DisburseToNeuron(self) == /\ pc[self] = "DisburseToNeuron"
                          /\ \/ /\ pc' = [pc EXCEPT ![self] = "Done"]
                                /\ UNCHANGED <<neuron, neuron_id_by_account, locks, governance_to_ledger, parent_neuron_id, disburse_amount, child_account_id, child_neuron_id>>
                             \/ /\ \E pnid \in DOMAIN(neuron) \ locks:
                                     LET parent_neuron == neuron[pnid] IN
                                       \E amt \in (MIN_STAKE + TRANSACTION_FEE)..(parent_neuron.cached_stake - parent_neuron.fees - MIN_STAKE):
                                         \E c_acc_id \in Governance_Account_Ids \ { neuron[n].account : n \in DOMAIN(neuron)}:
                                           /\ parent_neuron_id' = [parent_neuron_id EXCEPT ![self] = pnid]
                                           /\ disburse_amount' = [disburse_amount EXCEPT ![self] = amt]
                                           /\ parent_neuron.maturity <= TRANSACTION_FEE
                                           /\ child_account_id' = [child_account_id EXCEPT ![self] = c_acc_id]
                                           /\ child_neuron_id' = [child_neuron_id EXCEPT ![self] = FRESH_NEURON_ID(DOMAIN(neuron))]
                                           /\ neuron_id_by_account' = (child_account_id'[self] :> child_neuron_id'[self] @@ neuron_id_by_account)
                                           /\ neuron' = (child_neuron_id'[self] :> [ cached_stake |-> 0, account |-> child_account_id'[self], fees |-> 0, maturity |-> 0 ] @@ neuron)
                                           /\ Assert(child_neuron_id'[self] \notin locks,
                                                     "Failure of assertion at line 84, column 17.")
                                           /\ locks' = (locks \union {parent_neuron_id'[self], child_neuron_id'[self]})
                                           /\ governance_to_ledger' = Append(governance_to_ledger, request(self, (transfer(parent_neuron.account, child_account_id'[self], disburse_amount'[self] - TRANSACTION_FEE, TRANSACTION_FEE))))
                                /\ pc' = [pc EXCEPT ![self] = "DisburseToNeuron_WaitForTransfer"]
                          /\ UNCHANGED << ledger_to_governance,
                                          spawning_neurons >>

DisburseToNeuron_WaitForTransfer(self) == /\ pc[self] = "DisburseToNeuron_WaitForTransfer"
                                          /\ \E answer \in { resp \in ledger_to_governance: resp.caller = self}:
                                               /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                               /\ IF answer.response = Variant("Fail", UNIT)
                                                     THEN /\ neuron' = Remove_Arguments(neuron, {child_neuron_id[self]})
                                                          /\ neuron_id_by_account' = Remove_Arguments(neuron_id_by_account, {child_account_id[self]})
                                                     ELSE /\ neuron' =       [ neuron EXCEPT ![parent_neuron_id[self]].cached_stake = @ - disburse_amount[self],
                                                                       ![child_neuron_id[self]].cached_stake = disburse_amount[self] - TRANSACTION_FEE ]
                                                          /\ UNCHANGED neuron_id_by_account
                                               /\ locks' = locks \ {parent_neuron_id[self], child_neuron_id[self]}
                                               /\ parent_neuron_id' = [parent_neuron_id EXCEPT ![self] = 0]
                                               /\ disburse_amount' = [disburse_amount EXCEPT ![self] = 0]
                                               /\ child_account_id' = [child_account_id EXCEPT ![self] = DUMMY_ACCOUNT]
                                               /\ child_neuron_id' = [child_neuron_id EXCEPT ![self] = 0]
                                          /\ pc' = [pc EXCEPT ![self] = "Done"]
                                          /\ UNCHANGED << governance_to_ledger,
                                                          spawning_neurons >>

Disburse_To_Neuron(self) == DisburseToNeuron(self)
                               \/ DisburseToNeuron_WaitForTransfer(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in Disburse_To_Neuron_Process_Ids: Disburse_To_Neuron(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

====
