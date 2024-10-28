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
            await source_nid /= target_nid;
            source_neuron_id := source_nid;
            target_neuron_id := target_nid;

            \* Note that in the implementation this implies that child_neuron_id != parent_neuron_id,
            \* as the locks are taken sequentially there; here, we're sure that these neuron IDs differ,
            \* We have the explicit check earlier in this method that covers this.
            locks := locks \union {source_neuron_id, target_neuron_id};

            \* here the impl has a few guards:
            \* - caller must be controller of both source and target.
            \* - source must be younger than target
            \* - kyc_verified must match for both source and target
            \* - not_for_profit must match for both source and target
            \* - source neuron cannot be dedicated to community fund

            \* total stake cannot equal 0
            await (neuron[source_neuron_id].cached_stake - neuron[source_neuron_id].fees) +
                (neuron[target_neuron_id].cached_stake - neuron[target_neuron_id].fees) /= 0;

            fees_amount := neuron[source_neuron_id].fees;
            amount_to_target := Minted_Stake(neuron, source_neuron_id) - TRANSACTION_FEE;
            if(fees_amount > TRANSACTION_FEE) {
                \* The burning fee is 0, even though we check that the amounts are less than the transaction fee
                send_request(self, transfer(neuron[source_neuron_id].account, Minting_Account_Id, fees_amount, 0));
            }
            else {
                \* There's some code duplication here, but having to have the with statement
                \* span entire blocks to please Apalache, I don't have a better solution at the moment
                \* TODO: we don't burn the fees in this case in the code, do we?
                \* update_fees(source_neuron_id, fees_amount);
                if(amount_to_target > 0){
                    transfer_minted();
                    goto MergeNeurons_Transfer;
                } else {
                    goto MergeNeurons_End;
                }
            };
        };
    MergeNeurons_Burn:
        \* Note that we're here only because the fees amount was larger than the
        \* transaction fee (otherwise, the goto above would have taken us to MergeNeurons_Transfer/MergeNeurons_End)
        with(answer \in { resp \in ledger_to_governance: resp.caller = self}) {
            ledger_to_governance := ledger_to_governance \ {answer};
            if(answer.response = Variant("Fail", UNIT)) {
                goto MergeNeurons_End;
            }
            else {
                neuron := Decrease_Stake(Update_Fees(neuron, source_neuron_id, fees_amount),
                    source_neuron_id, amount_to_target + TRANSACTION_FEE);
                if(amount_to_target > 0) {
                    transfer_minted();
                    goto MergeNeurons_Transfer;
                } else {
                    goto MergeNeurons_End;
                }
            };
        };

    MergeNeurons_Transfer:
        with(answer \in { resp \in ledger_to_governance: resp.caller = self}) {
            ledger_to_governance := ledger_to_governance \ {answer};
            if(answer.response = Variant("Fail", UNIT)) {
                neuron := Increase_Stake(neuron, source_neuron_id, amount_to_target + TRANSACTION_FEE);
            } else {
                neuron := Increase_Stake(neuron, target_neuron_id, amount_to_target);
            };
        };
    MergeNeurons_End:
        locks := locks \ {source_neuron_id, target_neuron_id};
        reset_mn_vars();
    };
}
*)
\* BEGIN TRANSLATION (chksum(pcal) = "73eb42d9" /\ chksum(tla) = "87b1f24")
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
                                  /\ UNCHANGED <<locks, governance_to_ledger, source_neuron_id, target_neuron_id, fees_amount, amount_to_target>>
                               \/ /\ \E source_nid \in DOMAIN(neuron) \ locks:
                                       \E target_nid \in DOMAIN(neuron) \ locks:
                                         /\ source_nid /= target_nid
                                         /\ source_neuron_id' = [source_neuron_id EXCEPT ![self] = source_nid]
                                         /\ target_neuron_id' = [target_neuron_id EXCEPT ![self] = target_nid]
                                         /\ locks' = (locks \union {source_neuron_id'[self], target_neuron_id'[self]})
                                         /\   (neuron[source_neuron_id'[self]].cached_stake - neuron[source_neuron_id'[self]].fees) +
                                            (neuron[target_neuron_id'[self]].cached_stake - neuron[target_neuron_id'[self]].fees) /= 0
                                         /\ fees_amount' = [fees_amount EXCEPT ![self] = neuron[source_neuron_id'[self]].fees]
                                         /\ amount_to_target' = [amount_to_target EXCEPT ![self] = Minted_Stake(neuron, source_neuron_id'[self]) - TRANSACTION_FEE]
                                         /\ IF fees_amount'[self] > TRANSACTION_FEE
                                               THEN /\ governance_to_ledger' = Append(governance_to_ledger, request(self, (transfer(neuron[source_neuron_id'[self]].account, Minting_Account_Id, fees_amount'[self], 0))))
                                                    /\ pc' = [pc EXCEPT ![self] = "MergeNeurons_Burn"]
                                               ELSE /\ IF amount_to_target'[self] > 0
                                                          THEN /\ LET minted_stake == Minted_Stake(neuron, source_neuron_id'[self]) IN
                                                                    governance_to_ledger' = Append(governance_to_ledger, request(self, (transfer(neuron[source_neuron_id'[self]].account,
                                                                                                                                            neuron[target_neuron_id'[self]].account,
                                                                                                                                            Minted_Stake(neuron, source_neuron_id'[self]) - TRANSACTION_FEE,
                                                                                                                                            TRANSACTION_FEE))))
                                                               /\ pc' = [pc EXCEPT ![self] = "MergeNeurons_Transfer"]
                                                          ELSE /\ pc' = [pc EXCEPT ![self] = "MergeNeurons_End"]
                                                               /\ UNCHANGED governance_to_ledger
                            /\ UNCHANGED << neuron, neuron_id_by_account,
                                            ledger_to_governance >>

MergeNeurons_Burn(self) == /\ pc[self] = "MergeNeurons_Burn"
                           /\ \E answer \in { resp \in ledger_to_governance: resp.caller = self}:
                                /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                /\ IF answer.response = Variant("Fail", UNIT)
                                      THEN /\ pc' = [pc EXCEPT ![self] = "MergeNeurons_End"]
                                           /\ UNCHANGED << neuron,
                                                           governance_to_ledger >>
                                      ELSE /\ neuron' =       Decrease_Stake(Update_Fees(neuron, source_neuron_id[self], fees_amount[self]),
                                                        source_neuron_id[self], amount_to_target[self] + TRANSACTION_FEE)
                                           /\ IF amount_to_target[self] > 0
                                                 THEN /\ LET minted_stake == Minted_Stake(neuron', source_neuron_id[self]) IN
                                                           governance_to_ledger' = Append(governance_to_ledger, request(self, (transfer(neuron'[source_neuron_id[self]].account,
                                                                                                                                   neuron'[target_neuron_id[self]].account,
                                                                                                                                   Minted_Stake(neuron', source_neuron_id[self]) - TRANSACTION_FEE,
                                                                                                                                   TRANSACTION_FEE))))
                                                      /\ pc' = [pc EXCEPT ![self] = "MergeNeurons_Transfer"]
                                                 ELSE /\ pc' = [pc EXCEPT ![self] = "MergeNeurons_End"]
                                                      /\ UNCHANGED governance_to_ledger
                           /\ UNCHANGED << neuron_id_by_account, locks,
                                           source_neuron_id, target_neuron_id,
                                           fees_amount, amount_to_target >>

MergeNeurons_Transfer(self) == /\ pc[self] = "MergeNeurons_Transfer"
                               /\ \E answer \in { resp \in ledger_to_governance: resp.caller = self}:
                                    /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                    /\ IF answer.response = Variant("Fail", UNIT)
                                          THEN /\ neuron' = Increase_Stake(neuron, source_neuron_id[self], amount_to_target[self] + TRANSACTION_FEE)
                                          ELSE /\ neuron' = Increase_Stake(neuron, target_neuron_id[self], amount_to_target[self])
                               /\ pc' = [pc EXCEPT ![self] = "MergeNeurons_End"]
                               /\ UNCHANGED << neuron_id_by_account, locks,
                                               governance_to_ledger,
                                               source_neuron_id,
                                               target_neuron_id, fees_amount,
                                               amount_to_target >>

MergeNeurons_End(self) == /\ pc[self] = "MergeNeurons_End"
                          /\ locks' = locks \ {source_neuron_id[self], target_neuron_id[self]}
                          /\ source_neuron_id' = [source_neuron_id EXCEPT ![self] = 0]
                          /\ target_neuron_id' = [target_neuron_id EXCEPT ![self] = 0]
                          /\ fees_amount' = [fees_amount EXCEPT ![self] = 0]
                          /\ amount_to_target' = [amount_to_target EXCEPT ![self] = 0]
                          /\ pc' = [pc EXCEPT ![self] = "Done"]
                          /\ UNCHANGED << neuron, neuron_id_by_account,
                                          governance_to_ledger,
                                          ledger_to_governance >>

Merge_Neurons(self) == MergeNeurons_Start(self) \/ MergeNeurons_Burn(self)
                          \/ MergeNeurons_Transfer(self)
                          \/ MergeNeurons_End(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in Merge_Neurons_Process_Ids: Merge_Neurons(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

====
