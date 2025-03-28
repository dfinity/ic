This module adds Apalache type annotations and constant instantiations to the TLA model of split_neuron.

We can't add the annotations to Split_Neuron.tla (which contains the actual transition predicate)
because we use PlusCal. PlusCal autogenerates the TLA+ code, which means that every change to the
PlusCal code would overwrite the annotations on the VARIABLES.

Furthermore, when checking the code link with Apalache, we have to instantiate the constants.
Apalache requires us to do this in a separate module.

---- MODULE Split_Neuron_Apalache ----

EXTENDS TLC, Variants, Common_Apalache

\* This marker is necessary for the code link tooling to insert the constants
\* CODE_LINK_INSERT_CONSTANTS

(*
CONSTANTS
    \* @type: Set($account);
    Account_Ids,
    \* @type: Set($account);
    Governance_Account_Ids,
    \* @type: $account;
    Minting_Account_Id,
    \* @type: Set($neuronId);
    Neuron_Ids

CONSTANTS
    \* @type: Set($proc);
    Split_Neuron_Process_Ids

CONSTANTS
    \* Minimum stake a neuron can have
    \* @type: Int;
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    \* @type: Int;
    TRANSACTION_FEE
*)

VARIABLES
    \* @type: $neuronId -> {cached_stake: Int, account : $account, maturity: Int, fees: Int};
    neuron,
    \* @type: $account -> $neuronId;
    neuron_id_by_account,
    \* @type: Set($neuronId);
    locks,
    \* @type: Seq({caller : $proc, method_and_args: $methodCall });
    governance_to_ledger,
    \* @type: Set({caller: $proc, response: $methodResponse });
    ledger_to_governance,
    \* @type: $proc -> Str;
    pc,
    \* @type: $proc -> Int;
    sn_parent_neuron_id,
    \* @type: $proc -> Int;
    sn_amount,
    \* @type: $proc -> Int;
    sn_child_neuron_id,
    \* @type: $proc -> $account;
    sn_child_account_id,
    \* Not used by this model, but it's a global variable used by spawn_neurons, so
    \* it's the easiest to just add it to all the other models
    \* @type: Bool;
    spawning_neurons

\* @type: Set($neuronId) => $neuronId;
FRESH_NEURON_ID(existing_neurons) == CHOOSE nid \in (Neuron_Ids \ existing_neurons): TRUE

MOD == INSTANCE Split_Neuron

Next == [MOD!Next]_MOD!vars

====
