import P "mo:base/Prelude";
import Array "mo:base/Array";
import Nat "mo:base/Nat";
import Iter "mo:base/Iter";
import Prim "mo:prim";

actor {
    var myarray : [var Word8] = [var];
    var arraysize : Nat = 4096;
    var arraysize_to_write : Nat = 4096;
    var trap : Bool = false;

    public func init_array(size : Nat) {
        arraysize := size;
        myarray := Prim.Array_init<Word8>(arraysize, 0);
    };

    public query func get_current_size() : async Nat {
        return arraysize_to_write;
    };

    public func query_and_update(val : Word8, size : Nat) : async Nat {
        if (myarray.size() == 0) {
            Prim.debugPrint("array not initialized, initializing");
            return 0
        } else {
            arraysize_to_write :=  size;
            Prim.debugPrint("New Array Size to write " # Nat.toText(arraysize_to_write));
            
            for (i in Iter.range(0, arraysize_to_write)) {
                myarray[i] := val;
            };

            if (trap == true) {
                Prim.debugPrint("trapping");
                assert false;
            };
        };
        return arraysize_to_write
    };

    public func query_and_update_trapped() : async Nat {
        if (myarray.size() == 0) {
            Prim.debugPrint("array not initialized, initializing");
            return 0
        } else {

            var hi = myarray[arraysize_to_write];
            var lo = myarray[0];
            Prim.debugPrint("Array before processing" # Nat.toText(Prim.word8ToNat(lo)) # " " # Nat.toText(Prim.word8ToNat(hi)));

            hi += 1;

            arraysize_to_write :=  (arraysize_to_write + 4096) % arraysize;
            Prim.debugPrint("New Array Size to write " # Nat.toText(arraysize_to_write));
            
            for (i in Iter.range(0, arraysize_to_write)) {
                myarray[i] := hi;
            };

            hi := myarray[arraysize_to_write];
            lo := myarray[0];
            Prim.debugPrint("Array after processing" # Nat.toText(Prim.word8ToNat(lo)) # " " # Nat.toText(Prim.word8ToNat(hi)));
            
            Prim.debugPrint("trapping");
            assert false;

        };
        return arraysize_to_write
    };

    public query func compute_sum() : async Nat {
        var sum: Nat = 0;

        Prim.debugPrint("Query Array Size to write " # Nat.toText(arraysize_to_write));

        if (myarray.size() == 0) {
            Prim.debugPrint("array not initialized, initializing");
            // return "Array Not Initialized";
            return 0
        };

        for (i in Iter.range(1, arraysize-1)) {
            sum += Prim.word8ToNat(myarray[i]);  
        };

        // return "Sum is : " # Nat.toText(sum) # "!";
        return sum
    };

    public query func compute_sum_trapped() : async Text {
        var sum: Nat = 0;

        Prim.debugPrint("Query Array Size to write " # Nat.toText(arraysize_to_write));

        if (myarray.size() == 0) {
            Prim.debugPrint("array not initialized, initializing");
            return "Array Not Initialized";
        };

        for (i in Iter.range(1, arraysize-1)) {
            sum += Prim.word8ToNat(myarray[i]);  
        };

        Prim.debugPrint("trapping");
        assert false;

        return "Sum is : " # Nat.toText(sum) # "!";
    };

    public func toggle_trap() : async Text {
        trap := not trap;
        Prim.debugPrint("trap was reset");
        return "trap was reset !! ";
    };
};



