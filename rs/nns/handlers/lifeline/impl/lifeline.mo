// Refer to README.md for how to build this canister.

import Prim "mo:prim";
import Root "canister:root";
import Governance "canister:governance";

persistent actor {
    private transient let governanceCanister : Principal = Prim.principalOfActor Governance;
    private transient let root : Principal = Prim.principalOfActor Root;

    type UpgradeRootProposalPayload = {
      wasm_module : Blob;
      module_arg : Blob;
      stop_upgrade_start : Bool;
    };

    type HardResetRootToVersionPayload = {
      wasm_module : Blob;
      init_arg : Blob;
    };

    type CanisterIdRecord = { canister_id : Principal };

    type LogVisibility = {#controllers; #public_};

    type CanisterSettings = {
      controllers : ?[Principal];
      compute_allocation: ?Nat;
      memory_allocation: ?Nat;
      freezing_threshold: ?Nat;
      reserved_cycles_limit: ?Nat;
      wasm_memory_limit: ?Nat;
      log_visibility: ?LogVisibility;
      wasm_memory_threshold: ?Nat;
    };

    // IC00 is the management canister. We rely on it for the four
    // fundamental methods as listed below.
    private transient let ic00 = actor "aaaaa-aa" : actor {
      install_code : {
        mode : { #install; #reinstall; #upgrade };
        canister_id : Principal;
        wasm_module : Blob;
        arg : Blob;
      } -> async ();
      start_canister : CanisterIdRecord -> async ();
      stop_canister : CanisterIdRecord -> async ();
      uninstall_code : CanisterIdRecord -> async ();
      update_settings: {
        canister_id: Principal;
        settings: CanisterSettings;
      } -> async ();
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

    public shared ({caller}) func update_root_settings(settings: CanisterSettings) : async () {
      assert caller == governanceCanister;

      debug { Prim.debugPrint ("update_root_settings: about to update settings") };

      await ic00.update_settings({
        canister_id = root;
        settings = settings;
      });

      debug { Prim.debugPrint ("update_root_settings: finished updating settings") };
    };
}
