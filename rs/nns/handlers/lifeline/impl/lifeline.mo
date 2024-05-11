// Refer to README.md for how to build this canister.

import Prim "mo:prim";
import Root "canister:root";
import Governance "canister:governance";

actor {
    private let governanceCanister : Principal = Prim.principalOfActor Governance;
    private let root : Principal = Prim.principalOfActor Root;

    type UpgradeRootProposalPayload = { wasm_module : Blob; module_arg : Blob; stop_upgrade_start : Bool };
    type HardResetRootToVersionPayload = { wasm_module : Blob; init_arg : Blob; };

    // IC00 is the management canister. We rely on it for the four
    // fundamental methods as listed below.
    private let ic00 = actor "aaaaa-aa" : actor {
      install_code : {
        mode : { #install; #reinstall; #upgrade };
        canister_id : Principal;
        wasm_module : Blob;
        arg : Blob;
      } -> async ();
      start_canister : CanisterIdRecord -> async ();
      stop_canister : CanisterIdRecord -> async ();
      uninstall_code : CanisterIdRecord -> async ()
    };

    public shared ({caller}) func upgrade_root(pl : UpgradeRootProposalPayload) : async () {
      assert caller == governanceCanister;

      if (pl.stop_upgrade_start) {
        debug { Prim.debugPrint ("upgrade_root: stopping the root canister " # debug_show root) };
        try {
             await ic00.stop_canister({canister_id = root});
        } catch (err) {
             debug { Prim.debugPrint ("upgrade_root: failed to stop the root canister") };
             await ic00.start_canister({canister_id = root});
             return ();
        };
      };

      debug { Prim.debugPrint ("upgrade_root: about to actuate the management canister") };
      await ic00.install_code({
        mode = #upgrade;
        canister_id = root;
        wasm_module = pl.wasm_module;
        arg = pl.module_arg;
      });

      if (pl.stop_upgrade_start) {
        debug { Prim.debugPrint ("upgrade_root: starting the root canister") };
        await ic00.start_canister({canister_id = root});
      };

      debug { Prim.debugPrint "upgrade_root: upgraded the root canister" };
    };

    public shared ({caller}) func hard_reset_root_to_version(pl : HardResetRootToVersionPayload) : async () {
      assert caller == governanceCanister;

      debug { Prim.debugPrint ("hard_reset_root: uninstalling the root canister " # debug_show root) };
      await ic00.uninstall_code({canister_id = root});

      debug { Prim.debugPrint ("hard_reset_root: about to install a new root WASM") };
      await ic00.install_code({
        mode = #install;
        canister_id = root;
        wasm_module = pl.wasm_module;
        arg = pl.init_arg;
      });

      debug { Prim.debugPrint "hard_reset_root: finished installing" };
    };

    type CanisterIdRecord = { canister_id : Principal };

    type DefiniteCanisterSettings = {
        controllers : [Principal];

    };
}
