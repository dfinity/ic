actor {
    type WithdrawArgs = {
        amount : Nat;
        to : Principal;
    };

    type WithdrawResult = {
        #Ok : Nat;
        #Err : Text;
    };

    private let cycles_ledger = actor "aaaaa-aa" : actor {
        WithdrawArgs
        withdraw : WithdrawArgs -> async ({
           
        });
    };

    type RefundResult = {
        #Error : Text;
        #RefundedCycles : Nat;
    };

    public shared ({caller}) func refund(to : Principal) : async RefundResult {
        assert Prim.isController(caller);
        assert Prim.isController(to);

        let balance = Prim.cyclesBalance();

        balance
    };
}