// Refer to README.md for how to build this canister.

import Prim "mo:prim";
import Root "canister:root";
import Governance "canister:governance";

actor {
    private let governanceCanister : Principal = Prim.principalOfActor Governance;
    private let root : Principal = Prim.principalOfActor Root;

    type UpgradeRootProposalPayload = { wasm_module : Blob; module_arg : Blob; stop_upgrade_start : Bool };

    // IC00 is the management canister. We rely on it for the four
    // fundamental methods as listed below.
    private let ic00 = actor "aaaaa-aa" : actor {
      install_code : {
        mode : { #install; #reinstall; #upgrade };
        canister_id : Principal;
        wasm_module : Blob;
        arg : Blob;
        compute_allocation : ?Nat;
        memory_allocation : ?Nat;
        query_allocation : ?Nat;
      } -> async ();
      canister_status : CanisterIdRecord -> async CanisterStatusResult;
      start_canister : CanisterIdRecord -> async ();
      stop_canister : CanisterIdRecord -> async ()
    };

    public shared ({caller}) func upgrade_root(pl : UpgradeRootProposalPayload) : async () {
      assert caller == governanceCanister;

      if (pl.stop_upgrade_start) {
        debug { Prim.debugPrint ("upgrade_root: stopping the root canister " # debug_show root) };
        await ic00.stop_canister({canister_id = root});
      };

      debug { Prim.debugPrint ("upgrade_root: about to actuate the management canister") };
      await ic00.install_code({
        mode = #upgrade;
        canister_id = root;
        wasm_module = pl.wasm_module;
        arg = pl.module_arg;
        compute_allocation = null;
        memory_allocation = ?1073741824; // Root canister is given 1 GiB of memory.
        query_allocation = null
      });

      if (pl.stop_upgrade_start) {
        debug { Prim.debugPrint ("upgrade_root: starting the root canister") };
        await ic00.start_canister({canister_id = root});
      };

      debug { Prim.debugPrint "upgrade_root: upgraded the root canister" };
    };

    type CanisterIdRecord = { canister_id : Principal };

    type CanisterStatusResult = {
        controller : Principal;
        status : { #stopped; #stopping; #running };
        memory_size : Nat;
        module_hash : ?Blob;
        cycles : Nat;
        balance : [(Blob, Nat)]
    };

    public shared func canister_status(id : CanisterIdRecord) : async CanisterStatusResult {
      await ic00.canister_status(id);
    }
}
