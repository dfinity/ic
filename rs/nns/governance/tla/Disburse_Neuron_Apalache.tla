---- MODULE Disburse_Neuron_Apalache ----

EXTENDS TLC, Variants

(*
@typeAlias: proc = Str;
@typeAlias: account = Str;
@typeAlias: neuronId = Int;
@typeAlias: methodCall = Transfer({ from: $account, to: $account, amount: Int, fee: Int}) | AccountBalance({ account: $account });
@typeAlias: methodResponse = Fail(UNIT) | TransferOk(UNIT) | BalanceQueryOk(Int);
*)
_type_alias_dummy == TRUE

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
*)

VARIABLES
    \* @type: $neuronId -> {cached_stake: Int, account: $account, maturity: Int, fees: Int};
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
