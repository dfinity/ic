---- MODULE Spawn_Neurons_Apalache ----

EXTENDS TLC, Variants, Common_Apalache

\* This marker is necessary for the code link tooling to insert the constants
\* CODE_LINK_INSERT_CONSTANTS

(*
CONSTANTS
    \* @type: Set($account);
    Governance_Account_Ids,
    \* @type: $account;
    Minting_Account_Id,
    \* @type: Set($neuronId);
    Neuron_Ids

CONSTANTS
    \* @type: Set($proc);
    Spawn_Neurons_Process_Ids

CONSTANTS
    \* Minimum stake a neuron can have
    \* @type: Int;
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    \* @type: Int;
    TRANSACTION_FEE,
    \* @type: Int;
    MATURITY_BASIS_POINTS
*)

VARIABLES
    \* @type: Bool;
    spawning_neurons,
    \* @type: $proc -> $neuronId;
    neuron_id,
    \* @type: $proc -> Set($neuronId);
    ready_to_spawn_ids

MOD == INSTANCE Spawn_Neurons

Next == [MOD!Next]_MOD!vars

====
