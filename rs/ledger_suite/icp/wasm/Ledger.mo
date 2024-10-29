// This is a generated Motoko binding.
// didc bind -t mo ../ledger.did > Ledger.mo

module {
  public type AccountBalanceArgs = { account : AccountIdentifier };
  public type AccountIdentifier = [Nat8];
  public type Block = {
    transaction : Transaction;
    timestamp : TimeStamp;
    parent_hash : ?[Nat8];
  };
  public type BlockIndex = Nat64;
  public type BlockRange = { blocks : [Block] };
  public type GetBlocksArgs = { start : BlockIndex; length : Nat64 };
  public type Memo = Nat64;
  public type Operation = {
    #Burn : { from : AccountIdentifier; amount : Tokens };
    #Mint : { to : AccountIdentifier; amount : Tokens };
    #Transfer : {
      to : AccountIdentifier;
      fee : Tokens;
      from : AccountIdentifier;
      amount : Tokens;
    };
  };
  public type QueryArchiveError = {
    #BadFirstBlockIndex : {
      requested_index : BlockIndex;
      first_valid_index : BlockIndex;
    };
    #Other : { error_message : Text; error_code : Nat64 };
  };
  public type QueryArchiveFn = shared query GetBlocksArgs -> async QueryArchiveResult;
  public type QueryArchiveResult = {
    #Ok : BlockRange;
    #Err : QueryArchiveError;
  };
  public type QueryBlocksResponse = {
    certificate : ?[Nat8];
    blocks : [Block];
    chain_length : Nat64;
    first_block_index : BlockIndex;
    archived_blocks : [
      { callback : QueryArchiveFn; start : BlockIndex; length : Nat64 }
    ];
  };
  public type SubAccount = [Nat8];
  public type TimeStamp = { timestamp_nanos : Nat64 };
  public type Tokens = { e8s : Nat64 };
  public type Transaction = {
    memo : Memo;
    operation : ?Operation;
    created_at_time : TimeStamp;
  };
  public type TransferArgs = {
    to : AccountIdentifier;
    fee : Tokens;
    memo : Memo;
    from_subaccount : ?SubAccount;
    created_at_time : ?TimeStamp;
    amount : Tokens;
  };
  public type TransferError = {
    #TxTooOld : { allowed_window_nanos : Nat64 };
    #BadFee : { expected_fee : Tokens };
    #TxDuplicate : { duplicate_of : BlockIndex };
    #TxCreatedInFuture;
    #InsufficientFunds : { balance : Tokens };
  };
  public type TransferFee = { transfer_fee : Tokens };
  public type TransferFeeArg = {};
  public type TransferResult = { #Ok : BlockIndex; #Err : TransferError };
  public type Self = actor {
    account_balance : shared query AccountBalanceArgs -> async Tokens;
    decimals : shared query () -> async { decimals : Nat32 };
    name : shared query () -> async { name : Text };
    query_blocks : shared query GetBlocksArgs -> async QueryBlocksResponse;
    symbol : shared query () -> async { symbol : Text };
    transfer : shared TransferArgs -> async TransferResult;
    transfer_fee : shared query TransferFeeArg -> async TransferFee;
  }
}
