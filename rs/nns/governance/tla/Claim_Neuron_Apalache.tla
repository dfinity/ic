---- MODULE Claim_Neuron_Apalache ----


EXTENDS TLC, Variants

(*
@typeAlias: proc = Str;
@typeAlias: account = Str;
@typeAlias: neuronId = Int;
@typeAlias: accountBalanceMethodCall = AccountBalance({ account: $account });
@typeAlias: accountBalanceMethodResponse = Fail(UNIT) | Balance(Int);
*)
_type_alias_dummy == TRUE

\* CODE_LINK_INSERT_CONSTANTS

CONSTANTS 
    \* @type: Set($account);
    Account_Ids, 
    \* @type: Set($account);
    Governance_Account_Ids, 
    \* @type: Set($neuronId);
    Neuron_Ids

CONSTANTS 
    \* @type: Set($proc);
    Claim_Neuron_Process_Ids

CONSTANTS 
    \* Minimum stake a neuron can have
    \* @type: Int;
    MIN_STAKE
*)

VARIABLES
    \* @type: $neuronId -> {cached_stake: Int, account : $account, maturity: Int, fees: Int};
    neuron,
    \* @type: $account -> $neuronId;
    neuron_id_by_account,
    \* @type: Set($neuronId);
    locks,
    \* @type: Seq({caller : $proc, method_and_args: $accountBalanceMethodCall });
    governance_to_ledger,
    \* @type: Set({caller: $proc, response: $accountBalanceMethodResponse });
    ledger_to_governance,
    \* @type: $proc -> Str;
    pc,
    \* @type: $proc -> Int;
    neuron_id,
    \* @type: $proc -> Int;
    amount,
    \* @type: $proc -> $account;
    account_id

\* @type: Set($neuronId) => $neuronId;
FRESH_NEURON_ID(existing_neurons) == CHOOSE nid \in (Neuron_Ids \ existing_neurons): TRUE

MOD == INSTANCE Claim_Neuron

Next == [MOD!Next]_MOD!vars
