---- MODULE Refresh_Neuron_Apalache ----


EXTENDS TLC, Variants, Common_Apalache

\* CODE_LINK_INSERT_CONSTANTS

(*
CONSTANTS
    \* @type: Set($account);
    Account_Ids,
    \* @type: Set($account);
    Governance_Account_Ids

CONSTANTS
    \* @type: Set($proc);
    Refresh_Neuron_Process_Ids

CONSTANTS
    \* Minimum stake a neuron can have
    \* @type: Int;
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    \* @type: Int;
    TRANSACTION_FEE
*)

VARIABLES
    \* @type: $proc -> Int;
    neuron_id,
    \* Not used by this model, but it's a global variable used by spawn_neurons, so
    \* it's the easiest to just add it to all the other models
    \* @type: Bool;
    spawning_neurons

MOD == INSTANCE Refresh_Neuron

Next == [MOD!Next]_MOD!vars

====
