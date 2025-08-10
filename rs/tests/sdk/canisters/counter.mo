actor Counter {
    var cell : Nat = 0;

    public func inc() : async () {
        cell += 1;
    };

    public query func read() : async Nat {
        cell
    };

    public func inc_read() : async Nat {
        cell += 1;
        cell
    };

    public func write(n: Nat) : async () {
        cell := n;
    };
}
