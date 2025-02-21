---- MODULE Disburse_Neuron_Apalache ----

EXTENDS TLC, Variants, Common_Apalache, Integers

\* CODE_LINK_INSERT_CONSTANTS

(*
CONSTANTS
    \* @type: Set($account);
    Account_Ids,
    \* @type: Set($account);
    Governance_Account_Ids,
    \* @type: Set($neuronId);
    Neuron_Ids,
    \* @type: $account;
    Minting_Account_Id

CONSTANTS
    \* @type: Set($proc);
    Disburse_Neuron_Process_Ids

CONSTANTS
    \* Minimum stake a neuron can have
    \* @type: Int;
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    \* @type: Int;
    TRANSACTION_FEE

\* @type: ($neurons, $neuronId) => Set(Int);
POSSIBLE_DISBURSE_AMOUNTS(_neuron, _nid) == Nat
*)

VARIABLES
    \* Not used by this model, but it's a global variable used by spawn_neurons, so
    \* it's the easiest to just add it to all the other models
    \* @type: Bool;
    spawning_neurons,
    \* @type: $proc -> Int;
    neuron_id,
    \* @type: $proc -> Int;
    disburse_amount,
    \* @type: $proc -> $account;
    to_account,
    \* @type: $proc -> Int;
    fees_amount
 
MOD == INSTANCE Disburse_Neuron

Next == [MOD!Next]_MOD!vars

====
