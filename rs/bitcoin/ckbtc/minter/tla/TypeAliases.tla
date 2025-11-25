---- MODULE TypeAliases ----
EXTENDS TLC

(*
@typeAlias: principal = Str;
@typeAlias: btcAddress = Str;
@typeAlias: subaccount = Str;
@typeAlias: pid = Str;
@typeAlias: pc = $pid -> Str;
@typeAlias: txid = Str;
@typeAlias: utxoId = << $txid, Int >>;
@typeAlias: amount = Int;
@typeAlias: utxo = {id: $utxoId, owner: $btcAddress, amount: $amount};
$typeAlias: requestId = Int;
@typeAlias: withdrawalReq = {request_id: Int, address: $btcAddress, amount: $amount};
@typeAlias: outputEntry = {owner: $btcAddress, amount: $amount};
@typeAlias: submission = {consumed_utxos: Set($utxo), outputs: Seq($outputEntry)};
@typeAlias: txHashOp = TextHash(UNIT) | OtherHash($submission -> $txid);
@typeAlias: ckbtcAddress = { owner: $principal, subaccount: $subaccount };
@typeAlias: addressState = {discovered_utxos: Set($utxo), processed_utxos: Set($utxo), spent_utxos: Set($utxo)};
@typeAlias: submittedTx = {requests: Seq(Int), txid: $txid, used_utxos: Set($utxo), change_output: {vout: Int, vamount: $amount}};
@typeAlias: btcTransaction = {txid: $txid, consumed_utxos: Set($utxo), outputs: Seq($outputEntry)};
@typeAlias: minterToLedgerRequestType = Mint({to: $ckbtcAddress, amount: $amount}) | Burn({address: $ckbtcAddress, amount: $amount});
@typeAlias: minterToLedgerRequest = { 
    caller_id: $pid, 
    request: $minterToLedgerRequestType 
};
@typeAlias: ledgerToMinterResponseType = OK(UNIT) | Err(UNIT) | SystemErr(UNIT);
@typeAlias: ledgerToMinterResponse = { 
    caller_id: $pid,
    status: $ledgerToMinterResponseType
};
@typeAlias: minterToBtcCanisterRequestType = GetUtxos($btcAddress) | Submission($submission);
@typeAlias: minterToBtcCanisterRequest = { caller_id: $pid, request: $minterToBtcCanisterRequestType };
@typeAlias: btcCanisterToMinterResponseType = GetUtxosOk(Set($utxo)) | SubmissionOk(UNIT) | Error(UNIT);
@typeAlias: btcCanisterToMinterResponse = { 
    response: $btcCanisterToMinterResponseType,
    caller_id: $pid
};
@typeAlias: optSubmission = SomeSubmission($submission) | NoSubmission(UNIT);
*)
_type_alias_dummy == TRUE


====