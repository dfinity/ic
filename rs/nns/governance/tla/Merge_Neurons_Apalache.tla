---- MODULE Merge_Neurons_Apalache ----

EXTENDS TLC, Variants, Common_Apalache


\* CODE_LINK_INSERT_CONSTANTS

(*
CONSTANTS
    \* @type: Set($proc);
    Merge_Neurons_Process_Ids,
    \* @type: Set($neuronId);
    Neuron_Ids,
    \* @type: $accountId;
    Minting_Account_Id

CONSTANTS
    \* The transfer fee charged by the ledger canister
    \* @type: Int;
    TRANSACTION_FEE
*)

VARIABLES
    \* @type: $proc -> $neuronId;
    source_neuron_id,
    \* @type: $proc -> $neuronId;
    target_neuron_id,
    \* @type: $proc -> Int;
    fees_amount,
    \* @type: $proc -> Int;
    amount_to_target,
    \* Not used by this model, but it's a global variable used by spawn_neurons, so
    \* it's the easiest to just add it to all the other models
    \* @type: Bool;
    spawning_neurons

\* @type: Set($neuronId) => $neuronId;
FRESH_NEURON_ID(existing_neurons) == CHOOSE nid \in (Neuron_Ids \ existing_neurons): TRUE

MOD == INSTANCE Merge_Neurons

Next == [MOD!Next]_MOD!vars

====

====
