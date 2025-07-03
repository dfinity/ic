---- MODULE Common_Apalache ----
EXTENDS TLC

(*
@typeAlias: proc = Str;
@typeAlias: account = Str;
@typeAlias: neuronId = Int;
@typeAlias: methodCall = Transfer({ from: $account, to: $account, amount: Int, fee: Int}) | AccountBalance({ account: $account });
@typeAlias: methodResponse = Fail(UNIT) | TransferOk(UNIT) | BalanceQueryOk(Int);
@typeAlias: neuronState = NotSpawning(UNIT) | Spawning(UNIT);
@typeAlias: disbursement = { account_id: $account, amount: Int };
@typeAlias: neurons = $neuronId -> {cached_stake: Int, account: $account, maturity: Int, fees: Int, state: $neuronState, maturity_disbursements_in_progress: Seq($disbursement)};
*)
_type_alias_dummy == TRUE


VARIABLES
    \* @type: $neurons;
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
    pc

====
