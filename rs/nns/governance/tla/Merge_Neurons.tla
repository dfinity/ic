---- MODULE Merge_Neurons ----
EXTENDS TLC, Sequences, Naturals, FiniteSets, Variants

(*
@typeAlias: proc = Str;
@typeAlias: account = Str;
@typeAlias: neuronId = Int;
@typeAlias: methodCall = Transfer({ from: $account, to: $account, amount: Int, fee: Int}) | AccountBalance({ account: $account });
@typeAlias: methodResponse = Fail(UNIT) | TransferOk(UNIT) | BalanceQueryOk(Int);
@typeAlias: neurons = $neuronId -> {cached_stake: Int, account: $account, maturity: Int, fees: Int};
*)

_type_alias_dummy == TRUE

CONSTANTS
    Minting_Account_Id,
    Merge_Neurons_Process_Ids,
    TRANSACTION_FEE

OP_TRANSFER == "transfer"
TRANSFER_OK == "Ok"
TRANSFER_FAIL == "Err"
DUMMY_ACCOUNT == ""

\* @type: ($neurons, $neuronId) => Int;
Minted_Stake(neuron, neuron_id) == neuron[neuron_id].cached_stake - neuron[neuron_id].fees
request(caller, request_args) == [caller |-> caller, method_and_args |-> request_args]
transfer(from, to, amount, fee) == Variant("Transfer", [from |-> from, to |-> to, amount |-> amount, fee |-> fee])

\* @type: ($neurons, $neuronId, Int) => $neurons;
Decrease_Stake(neuron, neuron_id, amount) == [neuron EXCEPT ![neuron_id].cached_stake = @ - amount]
\* @type: ($neurons, $neuronId, Int) => $neurons;
Increase_Stake(neuron, neuron_id, amount) == [neuron EXCEPT ![neuron_id].cached_stake = @ + amount]
\* @type: ($neurons, $neuronId, Int) => $neurons;
Update_Fees(neuron, neuron_id, fees_amount) == [neuron EXCEPT
    ![neuron_id].cached_stake = LET diff == @ - fees_amount IN IF diff > 0 THEN diff ELSE 0,
    ![neuron_id].fees = 0 ]
\* @type: ($neurons, $neuronId, Int) => $neurons;
Decrease_Maturity(neuron, neuron_id, amount) == [neuron EXCEPT ![neuron_id].maturity = @ - amount]
\* @type: ($neurons, $neuronId, Int) => $neurons;
Increase_Maturity(neuron, neuron_id, amount) == [neuron EXCEPT ![neuron_id].maturity = @ + amount]


(* --algorithm Merge_Neurons {

variables

    neuron \in [{} -> {}];
    \* Used to decide whether we should refresh or claim a neuron
    neuron_id_by_account \in [{} -> {}];
    \* The set of currently locked neurons
    locks = {};
    \* The queue of messages sent from the governance canister to the ledger canister
    governance_to_ledger = <<>>;
    ledger_to_governance = {};

macro reset_mn_vars() {
    source_neuron_id := 0;
    target_neuron_id := 0;
    fees_amount := 0;
    amount_to_target := 0;
}

macro send_request(caller_id, request_args) {
    governance_to_ledger := Append(governance_to_ledger, request(caller_id, request_args))
};

macro transfer_minted() {
    with(minted_stake = Minted_Stake(neuron, source_neuron_id)) {
        send_request(self,
                transfer(neuron[source_neuron_id].account,
                    neuron[target_neuron_id].account,
                    Minted_Stake(neuron, source_neuron_id) - TRANSACTION_FEE,
                    TRANSACTION_FEE));
    }
}

macro adjust_maturities(neuron_changes) {
    neuron := Decrease_Maturity(
        Increase_Maturity(neuron_changes, target_neuron_id, neuron[source_neuron_id].maturity),
        target_neuron_id, neuron[source_neuron_id].maturity);
}

macro finish() {
    locks := locks \ {source_neuron_id, target_neuron_id };
    reset_mn_vars();
    goto Done;
}

macro maybe_transfer_stake(neuron_changes) {
    if(amount_to_target > 0) {
        locks := locks \union { source_neuron_id, target_neuron_id };
        source_neuron_id := source_nid;
        target_neuron_id := target_nid;
        amount_to_target := att;
        neuron := neuron_changes;
        transfer_minted();
        goto MergeNeurons_Transfer;
    } else {
        adjust_maturities(neuron_changes);
        finish();
    }
}

process ( Merge_Neurons \in Merge_Neurons_Process_Ids )
    variable
        \* These model the parameters of the call
        source_neuron_id = 0;
        target_neuron_id = 0;

        \* internal variables
        fees_amount = 0;
        amount_to_target = 0;
    {
    MergeNeurons_Start:
        either {
            \* Simulate calls that just fail early (e.g, due to failing checks) and
            \* don't change the state.
            \* Not so useful for model checking, but needed to follow the code traces.
            goto Done;
        } or with(source_nid \in DOMAIN(neuron) \ locks; target_nid \in DOMAIN(neuron) \ locks) {
            \* We block this branch of the process from starting where an error would be returned
            \* in the implementation
            \* Note that the sequential taking of locks in the implementation already implies that
            \* source_nid != target_nid, as the locks are taken sequentially there.
            \* Here, also we manually ensure that these neuron IDs differ.
            await source_nid /= target_nid;

            \* total stake cannot equal 0
            await (neuron[source_nid].cached_stake - neuron[source_nid].fees) +
                (neuron[target_neuron_id].cached_stake - neuron[target_neuron_id].fees) /= 0;


            \* here the impl has a few guards:
            \* - caller must be controller of both source and target.
            \* - source must be younger than target
            \* - kyc_verified must match for both source and target
            \* - not_for_profit must match for both source and target
            \* - source neuron cannot be dedicated to community fund

            with(fa = neuron[source_nid].fees; att = Minted_Stake(neuron, source_nid) - TRANSACTION_FEE) {
                if(fees_amount > TRANSACTION_FEE) {
                    \* This is a bit braindeaad, but seems necessary to work around PlusCal limitations.
                    \* Since we might unlock the neurons in the same message handler if we don't try to
                    \* burn the fees, and since the stupid PlusCal limitation prevents us from updating
                    \* the locks variable twice in the same block, we work around this by only locking
                    \* here conditionally. We'll also explicitly add the neurons to the locks again
                    \* if we want to transfer stake later on. This will be idempotent if they're already
                    \* locked, so it will behave the same as the implementation.
                    locks := locks \union {source_neuron_id, target_neuron_id};
                    \* Same for the local variables, they may get reset if the whole
                    \* update completes in a just a single message execution
                    source_neuron_id := source_nid;
                    target_neuron_id := target_nid;
                    fees_amount := fa;
                    amount_to_target := att;

                    \* The burning fee is 0, even though we check that the amounts are less than the transaction fee
                    send_request(self, transfer(neuron[source_neuron_id].account, Minting_Account_Id, fees_amount, 0));
                }
                else {
                    \* There's some code duplication here, but modeling the Rust control flow
                    \* in PlusCal is tricky, especially as we now have to match the labels 1-1
                    \* with the code link checker.
                    maybe_transfer_stake(neuron);
                };
            }
        };
    MergeNeurons_Burn:
        \* Note that we're here only because the fees amount was larger than the
        \* transaction fee (otherwise, the goto above would have taken us to MergeNeurons_Transfer/MergeNeurons_End)
        with(answer \in { resp \in ledger_to_governance: resp.caller = self}) {
            ledger_to_governance := ledger_to_governance \ {answer};
            if(answer.response = Variant("Fail", UNIT)) {
                finish();
            }
            else {
                \* The with here introduces some context to the macro, which reassigns
                \* source/target_neuron_id to themselves
                with(source_nid = source_neuron_id; target_nid = target_neuron_id; att = amount_to_target) {
                    maybe_transfer_stake(Decrease_Stake
                        (Update_Fees(neuron, source_neuron_id, fees_amount),
                        source_neuron_id, amount_to_target + TRANSACTION_FEE));
                }
            };
        };

    MergeNeurons_Transfer:
        with(answer \in { resp \in ledger_to_governance: resp.caller = self}) {
            ledger_to_governance := ledger_to_governance \ {answer};
            if(answer.response = Variant("Fail", UNIT)) {
                neuron := Increase_Stake(neuron, source_neuron_id, amount_to_target + TRANSACTION_FEE);
                finish();
            } else {
                adjust_maturities(Increase_Stake(neuron, target_neuron_id, amount_to_target));
                finish();
            };
        };
    }
}
*)
\* BEGIN TRANSLATION (chksum(pcal) = "d2161234" /\ chksum(tla) = "f54eb71c")
VARIABLES pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
          ledger_to_governance, source_neuron_id, target_neuron_id,
          fees_amount, amount_to_target

vars == << pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
           ledger_to_governance, source_neuron_id, target_neuron_id,
           fees_amount, amount_to_target >>

ProcSet == (Merge_Neurons_Process_Ids)

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}
        (* Process Merge_Neurons *)
        /\ source_neuron_id = [self \in Merge_Neurons_Process_Ids |-> 0]
        /\ target_neuron_id = [self \in Merge_Neurons_Process_Ids |-> 0]
        /\ fees_amount = [self \in Merge_Neurons_Process_Ids |-> 0]
        /\ amount_to_target = [self \in Merge_Neurons_Process_Ids |-> 0]
        /\ pc = [self \in ProcSet |-> "MergeNeurons_Start"]

MergeNeurons_Start(self) == /\ pc[self] = "MergeNeurons_Start"
                            /\ \/ /\ pc' = [pc EXCEPT ![self] = "Done"]
                                  /\ UNCHANGED <<neuron, locks, governance_to_ledger, source_neuron_id, target_neuron_id, fees_amount, amount_to_target>>
                               \/ /\ \E source_nid \in DOMAIN(neuron) \ locks:
                                       \E target_nid \in DOMAIN(neuron) \ locks:
                                         /\ source_nid /= target_nid
                                         /\   (neuron[source_nid].cached_stake - neuron[source_nid].fees) +
                                            (neuron[target_neuron_id[self]].cached_stake - neuron[target_neuron_id[self]].fees) /= 0
                                         /\ LET fa == neuron[source_nid].fees IN
                                              LET att == Minted_Stake(neuron, source_nid) - TRANSACTION_FEE IN
                                                IF fees_amount[self] > TRANSACTION_FEE
                                                   THEN /\ locks' = (locks \union {source_neuron_id[self], target_neuron_id[self]})
                                                        /\ source_neuron_id' = [source_neuron_id EXCEPT ![self] = source_nid]
                                                        /\ target_neuron_id' = [target_neuron_id EXCEPT ![self] = target_nid]
                                                        /\ fees_amount' = [fees_amount EXCEPT ![self] = fa]
                                                        /\ amount_to_target' = [amount_to_target EXCEPT ![self] = att]
                                                        /\ governance_to_ledger' = Append(governance_to_ledger, request(self, (transfer(neuron[source_neuron_id'[self]].account, Minting_Account_Id, fees_amount'[self], 0))))
                                                        /\ pc' = [pc EXCEPT ![self] = "MergeNeurons_Burn"]
                                                        /\ UNCHANGED neuron
                                                   ELSE /\ IF amount_to_target[self] > 0
                                                              THEN /\ locks' = (locks \union { source_neuron_id[self], target_neuron_id[self] })
                                                                   /\ source_neuron_id' = [source_neuron_id EXCEPT ![self] = source_nid]
                                                                   /\ target_neuron_id' = [target_neuron_id EXCEPT ![self] = target_nid]
                                                                   /\ amount_to_target' = [amount_to_target EXCEPT ![self] = att]
                                                                   /\ neuron' = neuron
                                                                   /\ LET minted_stake == Minted_Stake(neuron', source_neuron_id'[self]) IN
                                                                        governance_to_ledger' = Append(governance_to_ledger, request(self, (transfer(neuron'[source_neuron_id'[self]].account,
                                                                                                                                                neuron'[target_neuron_id'[self]].account,
                                                                                                                                                Minted_Stake(neuron', source_neuron_id'[self]) - TRANSACTION_FEE,
                                                                                                                                                TRANSACTION_FEE))))
                                                                   /\ pc' = [pc EXCEPT ![self] = "MergeNeurons_Transfer"]
                                                                   /\ UNCHANGED fees_amount
                                                              ELSE /\ neuron' =       Decrease_Maturity(
                                                                                Increase_Maturity(neuron, target_neuron_id[self], neuron[source_neuron_id[self]].maturity),
                                                                                target_neuron_id[self], neuron[source_neuron_id[self]].maturity)
                                                                   /\ locks' = locks \ {source_neuron_id[self], target_neuron_id[self] }
                                                                   /\ source_neuron_id' = [source_neuron_id EXCEPT ![self] = 0]
                                                                   /\ target_neuron_id' = [target_neuron_id EXCEPT ![self] = 0]
                                                                   /\ fees_amount' = [fees_amount EXCEPT ![self] = 0]
                                                                   /\ amount_to_target' = [amount_to_target EXCEPT ![self] = 0]
                                                                   /\ pc' = [pc EXCEPT ![self] = "Done"]
                                                                   /\ UNCHANGED governance_to_ledger
                            /\ UNCHANGED << neuron_id_by_account,
                                            ledger_to_governance >>

MergeNeurons_Burn(self) == /\ pc[self] = "MergeNeurons_Burn"
                           /\ \E answer \in { resp \in ledger_to_governance: resp.caller = self}:
                                /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                /\ IF answer.response = Variant("Fail", UNIT)
                                      THEN /\ locks' = locks \ {source_neuron_id[self], target_neuron_id[self] }
                                           /\ source_neuron_id' = [source_neuron_id EXCEPT ![self] = 0]
                                           /\ target_neuron_id' = [target_neuron_id EXCEPT ![self] = 0]
                                           /\ fees_amount' = [fees_amount EXCEPT ![self] = 0]
                                           /\ amount_to_target' = [amount_to_target EXCEPT ![self] = 0]
                                           /\ pc' = [pc EXCEPT ![self] = "Done"]
                                           /\ UNCHANGED << neuron,
                                                           governance_to_ledger >>
                                      ELSE /\ LET source_nid == source_neuron_id[self] IN
                                                LET target_nid == target_neuron_id[self] IN
                                                  LET att == amount_to_target[self] IN
                                                    IF amount_to_target[self] > 0
                                                       THEN /\ locks' = (locks \union { source_neuron_id[self], target_neuron_id[self] })
                                                            /\ source_neuron_id' = [source_neuron_id EXCEPT ![self] = source_nid]
                                                            /\ target_neuron_id' = [target_neuron_id EXCEPT ![self] = target_nid]
                                                            /\ amount_to_target' = [amount_to_target EXCEPT ![self] = att]
                                                            /\ neuron' =                  Decrease_Stake
                                                                         (Update_Fees(neuron, source_neuron_id'[self], fees_amount[self]),
                                                                         source_neuron_id'[self], amount_to_target'[self] + TRANSACTION_FEE)
                                                            /\ LET minted_stake == Minted_Stake(neuron', source_neuron_id'[self]) IN
                                                                 governance_to_ledger' = Append(governance_to_ledger, request(self, (transfer(neuron'[source_neuron_id'[self]].account,
                                                                                                                                         neuron'[target_neuron_id'[self]].account,
                                                                                                                                         Minted_Stake(neuron', source_neuron_id'[self]) - TRANSACTION_FEE,
                                                                                                                                         TRANSACTION_FEE))))
                                                            /\ pc' = [pc EXCEPT ![self] = "MergeNeurons_Transfer"]
                                                            /\ UNCHANGED fees_amount
                                                       ELSE /\ neuron' =       Decrease_Maturity(
                                                                         Increase_Maturity((                 Decrease_Stake
                                                                         (Update_Fees(neuron, source_neuron_id[self], fees_amount[self]),
                                                                         source_neuron_id[self], amount_to_target[self] + TRANSACTION_FEE)), target_neuron_id[self], neuron[source_neuron_id[self]].maturity),
                                                                         target_neuron_id[self], neuron[source_neuron_id[self]].maturity)
                                                            /\ locks' = locks \ {source_neuron_id[self], target_neuron_id[self] }
                                                            /\ source_neuron_id' = [source_neuron_id EXCEPT ![self] = 0]
                                                            /\ target_neuron_id' = [target_neuron_id EXCEPT ![self] = 0]
                                                            /\ fees_amount' = [fees_amount EXCEPT ![self] = 0]
                                                            /\ amount_to_target' = [amount_to_target EXCEPT ![self] = 0]
                                                            /\ pc' = [pc EXCEPT ![self] = "Done"]
                                                            /\ UNCHANGED governance_to_ledger
                           /\ UNCHANGED neuron_id_by_account

MergeNeurons_Transfer(self) == /\ pc[self] = "MergeNeurons_Transfer"
                               /\ \E answer \in { resp \in ledger_to_governance: resp.caller = self}:
                                    /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                    /\ IF answer.response = Variant("Fail", UNIT)
                                          THEN /\ neuron' = Increase_Stake(neuron, source_neuron_id[self], amount_to_target[self] + TRANSACTION_FEE)
                                               /\ locks' = locks \ {source_neuron_id[self], target_neuron_id[self] }
                                               /\ source_neuron_id' = [source_neuron_id EXCEPT ![self] = 0]
                                               /\ target_neuron_id' = [target_neuron_id EXCEPT ![self] = 0]
                                               /\ fees_amount' = [fees_amount EXCEPT ![self] = 0]
                                               /\ amount_to_target' = [amount_to_target EXCEPT ![self] = 0]
                                               /\ pc' = [pc EXCEPT ![self] = "Done"]
                                          ELSE /\ neuron' =       Decrease_Maturity(
                                                            Increase_Maturity((Increase_Stake(neuron, target_neuron_id[self], amount_to_target[self])), target_neuron_id[self], neuron[source_neuron_id[self]].maturity),
                                                            target_neuron_id[self], neuron[source_neuron_id[self]].maturity)
                                               /\ locks' = locks \ {source_neuron_id[self], target_neuron_id[self] }
                                               /\ source_neuron_id' = [source_neuron_id EXCEPT ![self] = 0]
                                               /\ target_neuron_id' = [target_neuron_id EXCEPT ![self] = 0]
                                               /\ fees_amount' = [fees_amount EXCEPT ![self] = 0]
                                               /\ amount_to_target' = [amount_to_target EXCEPT ![self] = 0]
                                               /\ pc' = [pc EXCEPT ![self] = "Done"]
                               /\ UNCHANGED << neuron_id_by_account,
                                               governance_to_ledger >>

Merge_Neurons(self) == MergeNeurons_Start(self) \/ MergeNeurons_Burn(self)
                          \/ MergeNeurons_Transfer(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in Merge_Neurons_Process_Ids: Merge_Neurons(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

====
