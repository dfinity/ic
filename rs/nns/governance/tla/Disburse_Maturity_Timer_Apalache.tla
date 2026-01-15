---- MODULE Disburse_Maturity_Timer_Apalache ----

EXTENDS TLC, Variants, Common_Apalache

\* This marker is necessary for the code link tooling to insert the constants
\* CODE_LINK_INSERT_CONSTANTS

(*
CONSTANTS
    \* @type: $account;
    Minting_Account_Id,
    \* @type: Set($neuronId);
    Neuron_Ids

CONSTANTS
    \* @type: Set($proc);
    Disburse_Maturity_Timer_Process_Ids

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
    \* @type: $proc -> $disbursement;
    current_disbursement

MOD == INSTANCE Disburse_Maturity_Timer

Next == [MOD!Next]_MOD!vars

====
