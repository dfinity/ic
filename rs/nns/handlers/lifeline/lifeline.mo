// Refer to README.md for how to build this canister.

import Prim "mo:prim";
import Root "canister:root";
import Governance "canister:governance";

actor class (auth : Any) { // auth is unused, kept for interface  compatibility
    private let governanceCanister : Principal = Prim.principalOfActor Governance;
    private let root : Principal = Prim.principalOfActor Root;

    type NeuronId = Nat64;
    type CreateUpgradeRootProposalPayload = { wasm_module : Blob; module_arg : Blob; stop_upgrade_start : Bool };
    // In order to capture an argument sequence as a Blob, we use the (jailbroken) `serialize`
    // primitive. See README.md for details.
    private func ser(b : Blob, a : Blob, d : Bool) : Blob = (prim "serialize" : (Blob, Blob, Bool) -> Blob) (b, a, d);

    /* Note: we could do away with this conversion by declaring the
            `Proposal` data type to refer to `Blob`. */
    private func blobToNat8Array(b : Blob) : [Nat8] {
      let vid : [var Nat8] = Prim.Array_init(b.size(), 0 : Nat8);
      var indx = 0;
      for (byte in b.bytes()) {
        vid[indx] := Prim.word8ToNat8 byte;
        indx := indx + 1
      };
      Prim.Array_tabulate(b.size(), func (i : Nat) : Nat8 = vid[i])
    };

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

    public shared ({caller}) func submit_upgrade_root_proposal(neuron_id: NeuronId, pl: CreateUpgradeRootProposalPayload) : async Governance.ProposalId {
      let prop : Governance.Proposal = {
        summary = "upgrade_root";
        url = "";
        action = ?(
          #ExecuteNnsFunction {
            nns_function = 9 : Int32; // inlined: NNS_FUNCTION_NNS_ROOT_UPGRADE
            // invariant: keep in sync with rs/nns/governance/proto/ic_nns_governance/pb/v1/governance.proto
            payload = blobToNat8Array(ser(pl.wasm_module, pl.module_arg, pl.stop_upgrade_start));
          }
        )
      };
      await Governance.submit_proposal(neuron_id, prop, caller);
    };

    public shared ({caller}) func upgrade_root(wasm : Blob, module_arg : Blob, stop_upgrade_start : Bool) : async () {
      assert caller == governanceCanister;

      if stop_upgrade_start {
        debug { Prim.debugPrint ("upgrade_root: stopping the root canister " # debug_show root) };
        await ic00.stop_canister({canister_id = root});
      };

      debug { Prim.debugPrint ("upgrade_root: about to actuate the management canister") };
      await ic00.install_code({
        mode = #upgrade;
        canister_id = root;
        wasm_module = wasm;
        arg = module_arg;
        compute_allocation = null;
        memory_allocation = ?1073741824; // Root canister is given 1 GiB of memory.
        query_allocation = null
      });

      if stop_upgrade_start {
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
