------------ MODULE Split_Neuron ------------
EXTENDS TLC, Sequences, Naturals, FiniteSets, Variants

CONSTANT
    FRESH_NEURON_ID(_)

CONSTANTS 
    Governance_Account_Ids, 
    Minting_Account_Id,
    Neuron_Ids

CONSTANTS 
    Split_Neuron_Process_Ids

CONSTANTS 
    \* Minimum stake a neuron can have
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    TRANSACTION_FEE

OP_TRANSFER == "transfer"
TRANSFER_OK == "Ok"
TRANSFER_FAIL == "Err"
DUMMY_ACCOUNT == ""

\* @type: (a -> b, Set(a)) => a -> b;
Remove_Arguments(f, S) == [ x \in (DOMAIN f \ S) |-> f[x]]

request(caller, request_args) == [caller |-> caller, method_and_args |-> request_args]
transfer(from, to, amount, fee) == Variant("Transfer", [from |-> from, to |-> to, amount |-> amount, fee |-> fee])

(* --algorithm Governance_Ledger_Split_Neuron {

variables 
    
    neuron \in [{} -> {}];
    \* Used to decide whether we should refresh or claim a neuron
    neuron_id_by_account \in [{} -> {}];
    \* The set of currently locked neurons
    locks = {};
    \* The queue of messages sent from the governance canister to the ledger canister
    governance_to_ledger = <<>>;
    ledger_to_governance = {};

macro sn_reset_local_vars() {
    sn_parent_neuron_id := 0;
    sn_amount := 0;
    sn_child_neuron_id := 0;
    sn_child_account_id := DUMMY_ACCOUNT;
}

process ( Split_Neuron \in Split_Neuron_Process_Ids )
    variable
        sn_parent_neuron_id = 0;
        sn_amount = 0;

        \* internal variables
        sn_child_neuron_id = 0;
        sn_child_account_id = DUMMY_ACCOUNT;

    {
    SplitNeuron1:
        either {
            \* Simulate early failed calls that don't change the state; 
            \* not so useful for model checking, but needed to follow the code traces.
            goto Done;
        } or {
        \* Need to make sure there is an element of Split_Neuron_Account_Ids for each
        \* member of Split_Neuron_Process_Ids
        with(nid \in DOMAIN(neuron) \ locks; 
             amt \in 0..neuron[nid].cached_stake; 
             fresh_account_id \in Governance_Account_Ids \ {neuron[n].account : n \in DOMAIN(neuron)};
            ) {
            sn_parent_neuron_id := nid;
            sn_amount := amt;
            sn_child_account_id := fresh_account_id;

            \* Get a fresh neuron ID
            sn_child_neuron_id := FRESH_NEURON_ID(DOMAIN(neuron));
            assert sn_child_neuron_id \notin locks;  \* should be redundant

            await(sn_amount >= MIN_STAKE + TRANSACTION_FEE /\ neuron[sn_parent_neuron_id].cached_stake - neuron[sn_parent_neuron_id].fees >= MIN_STAKE + sn_amount);

            \* Note that in the implementation this implies that child_neuron_id != parent_neuron_id,
            \* as the locks are taken sequentially there; here, we're sure that these neuron IDs differ,
            \* so we omit the extra check.
            locks := locks \union {sn_parent_neuron_id, sn_child_neuron_id};
            neuron := sn_child_neuron_id :> [ cached_stake |-> 0, account |-> sn_child_account_id, fees |-> 0, maturity |-> 0 ] @@ 
                [neuron EXCEPT ![sn_parent_neuron_id] = [@ EXCEPT !.cached_stake = @ - sn_amount ] ];
            neuron_id_by_account := sn_child_account_id :> sn_child_neuron_id @@ neuron_id_by_account;

            governance_to_ledger := Append(governance_to_ledger, 
                request(self, transfer(neuron[sn_parent_neuron_id].account, neuron[sn_child_neuron_id].account, sn_amount - TRANSACTION_FEE, TRANSACTION_FEE)));
        };
        };
    WaitForTransfer:
        with(answer \in { resp \in ledger_to_governance: resp.caller = self}) {
            ledger_to_governance := ledger_to_governance \ {answer};
            if(answer.response = Variant("Fail", UNIT)) {
                neuron := LET new_n == Remove_Arguments(neuron, {sn_child_neuron_id})
                    IN [new_n EXCEPT ![sn_parent_neuron_id] = [ @ EXCEPT !.cached_stake = @ + sn_amount ] ];
                neuron_id_by_account := Remove_Arguments(neuron_id_by_account, {sn_child_account_id});
            } else {
                \* the rust impl should but does not use saturating arithmetic.
                with(
                    maturity_to_transfer = (neuron[sn_parent_neuron_id].maturity * sn_amount) \div (neuron[sn_parent_neuron_id].cached_stake + sn_amount)
                ) {
                    neuron := [neuron EXCEPT 
                        ![sn_child_neuron_id] = [ @ EXCEPT !.cached_stake = sn_amount - TRANSACTION_FEE, !.maturity = maturity_to_transfer ],
                        ![sn_parent_neuron_id] = [ @ EXCEPT !.maturity = @ - maturity_to_transfer ]];
                }
            };
            locks := locks \ {sn_child_neuron_id, sn_parent_neuron_id};
        };
        sn_reset_local_vars();
    };

} 
*)
\* BEGIN TRANSLATION (chksum(pcal) = "2f818cef" /\ chksum(tla) = "a6539bfe")
VARIABLES pc, neuron, neuron_id_by_account, locks, governance_to_ledger, 
          ledger_to_governance, sn_parent_neuron_id, sn_amount, 
          sn_child_neuron_id, sn_child_account_id

vars == << pc, neuron, neuron_id_by_account, locks, governance_to_ledger, 
           ledger_to_governance, sn_parent_neuron_id, sn_amount, 
           sn_child_neuron_id, sn_child_account_id >>

ProcSet == (Split_Neuron_Process_Ids)

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}
        (* Process Split_Neuron *)
        /\ sn_parent_neuron_id = [self \in Split_Neuron_Process_Ids |-> 0]
        /\ sn_amount = [self \in Split_Neuron_Process_Ids |-> 0]
        /\ sn_child_neuron_id = [self \in Split_Neuron_Process_Ids |-> 0]
        /\ sn_child_account_id = [self \in Split_Neuron_Process_Ids |-> DUMMY_ACCOUNT]
        /\ pc = [self \in ProcSet |-> "SplitNeuron1"]

SplitNeuron1(self) == /\ pc[self] = "SplitNeuron1"
                      /\ \/ /\ pc' = [pc EXCEPT ![self] = "Done"]
                            /\ UNCHANGED <<neuron, neuron_id_by_account, locks, governance_to_ledger, sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id>>
                         \/ /\ \E nid \in DOMAIN(neuron) \ locks:
                                 \E amt \in 0..neuron[nid].cached_stake:
                                   \E fresh_account_id \in Governance_Account_Ids \ {neuron[n].account : n \in DOMAIN(neuron)}:
                                     /\ sn_parent_neuron_id' = [sn_parent_neuron_id EXCEPT ![self] = nid]
                                     /\ sn_amount' = [sn_amount EXCEPT ![self] = amt]
                                     /\ sn_child_account_id' = [sn_child_account_id EXCEPT ![self] = fresh_account_id]
                                     /\ sn_child_neuron_id' = [sn_child_neuron_id EXCEPT ![self] = FRESH_NEURON_ID(DOMAIN(neuron))]
                                     /\ Assert(sn_child_neuron_id'[self] \notin locks, 
                                               "Failure of assertion at line 80, column 13.")
                                     /\ (sn_amount'[self] >= MIN_STAKE + TRANSACTION_FEE /\ neuron[sn_parent_neuron_id'[self]].cached_stake - neuron[sn_parent_neuron_id'[self]].fees >= MIN_STAKE + sn_amount'[self])
                                     /\ locks' = (locks \union {sn_parent_neuron_id'[self], sn_child_neuron_id'[self]})
                                     /\ neuron' = (      sn_child_neuron_id'[self] :> [ cached_stake |-> 0, account |-> sn_child_account_id'[self], fees |-> 0, maturity |-> 0 ] @@
                                                   [neuron EXCEPT ![sn_parent_neuron_id'[self]] = [@ EXCEPT !.cached_stake = @ - sn_amount'[self] ] ])
                                     /\ neuron_id_by_account' = (sn_child_account_id'[self] :> sn_child_neuron_id'[self] @@ neuron_id_by_account)
                                     /\ governance_to_ledger' =                     Append(governance_to_ledger,
                                                                request(self, transfer(neuron'[sn_parent_neuron_id'[self]].account, neuron'[sn_child_neuron_id'[self]].account, sn_amount'[self] - TRANSACTION_FEE, TRANSACTION_FEE)))
                            /\ pc' = [pc EXCEPT ![self] = "WaitForTransfer"]
                      /\ UNCHANGED ledger_to_governance

WaitForTransfer(self) == /\ pc[self] = "WaitForTransfer"
                         /\ \E answer \in { resp \in ledger_to_governance: resp.caller = self}:
                              /\ ledger_to_governance' = ledger_to_governance \ {answer}
                              /\ IF answer.response = Variant("Fail", UNIT)
                                    THEN /\ neuron' = (      LET new_n == Remove_Arguments(neuron, {sn_child_neuron_id[self]})
                                                       IN [new_n EXCEPT ![sn_parent_neuron_id[self]] = [ @ EXCEPT !.cached_stake = @ + sn_amount[self] ] ])
                                         /\ neuron_id_by_account' = Remove_Arguments(neuron_id_by_account, {sn_child_account_id[self]})
                                    ELSE /\ LET maturity_to_transfer == (neuron[sn_parent_neuron_id[self]].maturity * sn_amount[self]) \div (neuron[sn_parent_neuron_id[self]].cached_stake + sn_amount[self]) IN
                                              neuron' =       [neuron EXCEPT
                                                        ![sn_child_neuron_id[self]] = [ @ EXCEPT !.cached_stake = sn_amount[self] - TRANSACTION_FEE, !.maturity = maturity_to_transfer ],
                                                        ![sn_parent_neuron_id[self]] = [ @ EXCEPT !.maturity = @ - maturity_to_transfer ]]
                                         /\ UNCHANGED neuron_id_by_account
                              /\ locks' = locks \ {sn_child_neuron_id[self], sn_parent_neuron_id[self]}
                         /\ sn_parent_neuron_id' = [sn_parent_neuron_id EXCEPT ![self] = 0]
                         /\ sn_amount' = [sn_amount EXCEPT ![self] = 0]
                         /\ sn_child_neuron_id' = [sn_child_neuron_id EXCEPT ![self] = 0]
                         /\ sn_child_account_id' = [sn_child_account_id EXCEPT ![self] = DUMMY_ACCOUNT]
                         /\ pc' = [pc EXCEPT ![self] = "Done"]
                         /\ UNCHANGED governance_to_ledger

Split_Neuron(self) == SplitNeuron1(self) \/ WaitForTransfer(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in Split_Neuron_Process_Ids: Split_Neuron(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 


====
