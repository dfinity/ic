---- MODULE Spawn_Neuron_Apalache ----

EXTENDS TLC, Variants

(*
@typeAlias: proc = Str;
@typeAlias: account = Str;
@typeAlias: neuronId = Int;
@typeAlias: methodCall = Transfer({ from: $account, to: $account, amount: Int, fee: Int}) | AccountBalance({ account_id: $account });
@typeAlias: methodResponse = Fail(UNIT) | TransferOk(UNIT) | BalanceQueryOk(Int);
*)
_type_alias_dummy == TRUE

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
    Spawn_Neuron_Process_Ids

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
    \* Not used by this model, but it's a global variable used by spawn_neurons, so
    \* it's the easiest to just add it to all the other models
    \* @type: Bool;
    spawning_neurons

\* @type: Set($neuronId) => $neuronId;
FRESH_NEURON_ID(existing_neurons) == CHOOSE nid \in (Neuron_Ids \ existing_neurons): TRUE

MOD == INSTANCE Spawn_Neuron

Next == [MOD!Next]_MOD!vars

====