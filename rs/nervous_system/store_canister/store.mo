import Prim "mo:prim";

actor class (authorized_principal : Principal) {
    type WithdrawArgs = {
        amount : Nat;
        to : Principal;
    };

    type WithdrawResult = {
        #Ok : Nat;
        #Err : Text;
    };

    private let cyclesLedger = actor "um5iw-rqaaa-aaaaq-qaaba-cai" : actor {
        withdraw : (WithdrawArgs) -> async (WithdrawResult);
    };

    public shared ({caller}) func withdraw_cycles(to : Principal) : async WithdrawResult {
        assert caller == authorized_principal;

        let balance = Prim.cyclesBalance();

        await cyclesLedger.withdraw({
            amount = balance;
            to = to;
        })
    }
}