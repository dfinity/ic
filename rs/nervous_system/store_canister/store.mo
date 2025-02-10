import Prim "mo:prim";

actor class (authorized_principal : Principal) {
    // Approximate amount of cycles that this canister cannot operate without.
    private let RESERVED_CYCLES: Nat = 100_000_000_000;

    type Account = {
        owner : Principal;
        subaccount : ?Blob;
    };

    type DepositArgs = {
        to : Account;
        memo : ?Blob;
    };

    type DepositResult = {
        balance : Nat;
        block_index : Nat;
    };

    private let cyclesLedger = actor "um5iw-rqaaa-aaaaq-qaaba-cai" : actor {
        deposit : (DepositArgs) -> async (DepositResult);
    };

    public shared ({caller}) func withdraw_cycles(to : Principal) : async Nat {
        assert caller == authorized_principal;

        let balance = Prim.cyclesBalance();
        if (balance <= RESERVED_CYCLES) {
            return 0;
        };
        let withdraw_amount = balance - RESERVED_CYCLES;

        Prim.cyclesAdd(withdraw_amount);

        let _ = await cyclesLedger.deposit({
            to = {
                owner = authorized_principal;
                subaccount = null;
            };
            memo = null;
        });

        withdraw_amount
    };
}