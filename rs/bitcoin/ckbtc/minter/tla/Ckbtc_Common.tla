---- MODULE Ckbtc_Common ----
EXTENDS TLC, Sequences, Integers, FiniteSets, FiniteSetsExt, SequencesExt, Functions, Variants, Apalache, TLA_Hash, TypeAliases

CONSTANTS
    \**********************************************************************************************
    \* Constants determining the model size
    \**********************************************************************************************
    \* Principals that hold ckBTC
    \* @type: Set($principal);
    PRINCIPALS,
    \* Subaccounts for the ck_btc_addresses
    \* @type: Set($subaccount);
    SUBACCOUNTS,
    \* Every BTC transfer allocates a new UTXO id. Allowing an infinite number of transfers
    \* would thus require infinite state. So we bound the number of BTC transfers a user is
    \* allowed to make.
    \* Minter principal
    \* @type: $principal;
    MINTER_PRINCIPAL,
    \* Minter change subaccount
    \* @type: $subaccount;
    MINTER_SUBACCOUNT,
    \* @type: $txHashOp;
    TX_HASH_OP


MINTER_CKBTC_ADDRESS == [owner |-> MINTER_PRINCIPAL, subaccount |-> MINTER_SUBACCOUNT]

\* CK_BTC addresses
CK_BTC_ADDRESSES == [owner:PRINCIPALS, subaccount: SUBACCOUNTS]

\* The version of BURN_ADDRESS used with TLC for analysis, as TLC doesn't care about types
\* @type: $principal => $ckbtcAddress;
BURN_ADDRESS(p) == [owner |-> MINTER_PRINCIPAL, subaccount |-> p]


\**********************************************************************************************
(* Some general auxiliary definitions on sets, functions etc. *)
\**********************************************************************************************

Proper_Subsets(S) == SUBSET S \ {S}

\* @type: (a => Int, Set(a)) => Int;
Sum_F(f(_), S) == FoldSet(LAMBDA x, y: f(x) + y, 0, S)

\* @type: (a -> b, a, b) => b;
With_Default(f, x, default) == IF x \in DOMAIN f THEN f[x] ELSE default

\* @type: (a -> b, Set(a)) => (a -> b);
Remove_Arguments(f, S) == [ x \in (DOMAIN f \ S) |-> f[x] ]
\* @type: (a -> b, a) => (a -> b);
Remove_Argument(f, x) == Remove_Arguments(f, {x})

\* @type: (a -> b, Set(a)) => Set(b);
Image(f, S) == { f[x] : x \in S }

\* @type: Set(a -> b);
Empty_Funs == [ {} -> {} ]

\* @type: (a => b, Seq(a)) => Seq(b);
Map(f(_), seq) == FoldRight(LAMBDA x, y: <<f(x)>> \o y, seq, <<>>)

\* @type: Seq(Int) => Int;
Sum_Seq(seq) == FoldRight(LAMBDA x, y: x + y, seq, 0)

\* Definitions on UTXO sets
\* @type: (Int, $utxo) => Int;
Add_Utxo_Amount(amt, utxo) == utxo.value + amt
\* @type: Set($utxo) => $value;
Sum_Utxos(S) == \* Sum_F(LAMBDA x: x.amount, S)
                ApaFoldSet(Add_Utxo_Amount, 0, S)
\* @type: (Set({owner: $btcAddress, b}), Set($btcAddress)) => Set({owner: $btcAddress, b});
Utxos_Owned_By(utxos, S) == { utxo \in utxos: utxo.owner \in S }

\* @type: { status: $ledgerToMinterResponseType, b } => $ledgerToMinterResponseType;
Status(msg) == msg.status

\* "Standard" inter-canister message definitions, used for communication between any pair of canisters.
\* E.g., whether a response is an error or not, what the PID of the caller of a request is, etc.
Status_Ok == Variant("OK", UNIT)
Status_Err == Variant("Err", UNIT)
Status_System_Err == Variant("SystemErr", UNIT)
Is_Ok(status) == VariantTag(status) = "OK"
Is_System_Err(status) == VariantTag(status) = "SystemErr"



\* Auxiliary definitions for specific kinds of messages (e.g., a get_utxos request)
\* @type: ($pid, $btcAddress) => $minterToBtcCanisterRequest;
Get_Utxos_Request(caller_id, btc_address) == [
    caller_id |-> caller_id,
    request |-> Variant("GetUtxos", btc_address)
]
\* @type: $minterToBtcCanisterRequest => Bool;
Is_Get_Utxos_Request(req) == VariantTag(req.request) = "GetUtxos"
\* @type: $minterToBtcCanisterRequest => $btcAddress;
Get_Utxos_Request_Address(req) == VariantGetUnsafe("GetUtxos", req.request)

\* @type: { caller_id: $pid, b } => $pid;
Caller(msg) == msg.caller_id

Mint_Request(caller_id, to_address, amount) == [
    request |-> Variant("Mint", [ to |-> to_address, amount |-> amount ]),
    caller_id |-> caller_id
]
\* @type: $minterToLedgerRequest => Bool;
Is_Mint_Request(req) == VariantTag(req.request) = "Mint"

Burn_Request(caller_id, address, amount) == [
    request |-> Variant("Burn", [ address |-> address, amount |-> amount ]),
    caller_id |-> caller_id
]
\* @type: $minterToLedgerRequest => Bool;
Is_Burn_Request(req) == VariantTag(req.request) = "Burn"

\* @type: (Set($utxo), Seq({ address: $btcAddress, value: $value, b }), $btcAddress) => Seq($outputEntry);
New_Outputs(utxos, requests, change_address) ==
    LET
        total_available == Sum_Utxos(utxos)
        \* Apalache doesn't seem to like lambdas, so introduce a definition
        \* @type: { address: $btcAddress, value: $value } => $value;
        get_amt(request) == request.value
        total_requested == Sum_Seq(Map(get_amt, requests))
        change == total_available - total_requested
        parent_ids == { utxo.id : utxo \in utxos }
        \* @type: { address: $btcAddress, value: $value } => { owner: $btcAddress, value: $value };
        mk_record(request) == [ owner |-> request.address, value |-> request.value ]
        new_outputs == Map(mk_record, requests)
    IN
        new_outputs \o
        IF change > 0 THEN << [ owner |-> change_address, value |-> change ] >> ELSE << >>

Submission_Request(caller_id, submission) == [
    caller_id |-> caller_id,
    request |-> Variant("Submission", submission)
]
\* @type: $minterToBtcCanisterRequest => Bool;
Is_Submission_Request(req) == VariantTag(req.request) = "Submission"

\* @type: ($pid, Set($utxo)) => $btcCanisterToMinterResponse;
Get_Utxos_Response(caller_id, utxos) == [ caller_id |-> caller_id, response |-> Variant("GetUtxosOk", utxos) ]
\* @type: $btcCanisterToMinterResponse => Bool;
Is_Get_Utxos_Ok_Response(resp) == VariantTag(resp.response) = "GetUtxosOk"

\* @type: $btcCanisterToMinterResponse => Set($utxo);
Get_Utxos_Result(resp) == VariantGetUnsafe("GetUtxosOk", resp.response)

\* @type: $submission => $txid;
Tx_Hash(tx) == IF VariantTag(TX_HASH_OP) = "TextHash" 
                THEN ToString(tx) 
                ELSE VariantGetUnsafe("OtherHash", TX_HASH_OP)[tx]

====