import Ledger "canister:ledger";
import Prim "mo:prim"


/*
/nix/store/62mpdxszlrj5j2048pjdmm4b6ls3xc6y-moc/bin/moc -o transaction_ledger_correctness.wasm transaction_ledger_correctness.mo --actor-alias ledger "ryjl3-tyaaa-aaaaa-aaaba-cai" --actor-idl .

/nix/store/62mpdxszlrj5j2048pjdmm4b6ls3xc6y-moc/bin/moc --idl -o transaction_ledger_correctness.did transaction_ledger_correctness.mo --actor-alias ledger "ryjl3-tyaaa-aaaaa-aaaba-cai" --actor-idl . && cat transaction_ledger_correctness.did
*/

actor Self {
    let nothing : Ledger.ICP = { e8s = 0 };
    let fee : Ledger.ICP = { e8s = 10000 };

    func balanceArgs(owner : Ledger.Address) : Ledger.AccountBalanceArgs = { account = owner };

    public func check_and_send(accnt : Ledger.Address, iHave : Ledger.ICP, to : Ledger.Address, toHas : Ledger.ICP, amount : Ledger.ICP)
                : async ?Ledger.BlockHeight {
        Prim.debugPrint(debug_show accnt);
        Prim.debugPrint(debug_show to);
        // verify that I have the right amount of funds
        let funds = await Ledger.account_balance(balanceArgs accnt);
        Prim.debugPrint("ASSERTING: " # debug_show iHave # ", " # debug_show funds);
        assert iHave == funds;
        if (accnt != to) {
            // verify that other side has the right amount of funds
            let otherFunds = await Ledger.account_balance(balanceArgs to);
            Prim.debugPrint("ASSERTING2: " # debug_show toHas # " == " # debug_show otherFunds);
            assert toHas == otherFunds;
        };
        try {
            Prim.debugPrint("TRANSFERRING: " # debug_show amount # ", " # debug_show (Prim.principalOfActor Self) # ", TO: " # debug_show to);
            let res = await Ledger.transfer({ memo = 42;
                                              amount = amount;
                                              fee = fee;
                                              from_subaccount = null;
                                              to = to;
                                              created_at_time = null });
            switch (res) {
              case (#Ok(tip)) { ?tip };
              case (#Err(#BadFee { expected_fee })) {
                Prim.debugPrint("ERROR: bad fee " # debug_show fee # ", expected fee: " # debug_show expected_fee);
                null
              };
              case (#Err(#InsufficientFunds { balance })) {
                Prim.debugPrint("ERROR: insufficient funds, balance: " # debug_show balance);
                null
              };
              case (#Err(#TxTooOld { allowed_window_nanos })) {
                Prim.debugPrint("ERROR: transaction too old, allowed window: " # debug_show allowed_window_nanos);
                null
              };
              case (#Err(#TxCreatedInFuture)) {
                Prim.debugPrint("ERROR: transaction created in future");
                null
              };
              case (#Err(#TxDuplicate { duplicate_of })) {
                Prim.debugPrint("ERROR: transaction is a duplicate of the transaction in block " # debug_show duplicate_of);
                null
              };
            };
        } catch e {
            Prim.debugPrint(debug_show (Prim.errorCode e, Prim.errorMessage e));
            assert iHave.e8s < amount.e8s + fee.e8s;
            null
        };
    }
}
