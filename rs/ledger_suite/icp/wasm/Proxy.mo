import Prim "mo:prim";
import Ledger "./Ledger";

/*
/nix/store/62mpdxszlrj5j2048pjdmm4b6ls3xc6y-moc/bin/moc -o ledger_proxy.wasm Proxy.mo
*/

actor Self {

  // Query blocks in the specified range from the [ledger] canister and check
  // that they equal to [result].
  public func testQueryBlocks({
      ledger : Principal;
      arg : { start : Nat64; length : Nat64 };
      result : [Ledger.Block];
    }) : async () {
      let ledgerActor = asLedger(ledger);
      let blocks = await fetch(ledgerActor, arg);

      Prim.debugPrint("Expected blocks: " # debug_show result);
      Prim.debugPrint("Actual blocks:   " # debug_show blocks);
      assert debug_show(blocks) == debug_show(result);
  };

  // Casts a principal to the Ledger actor interface.
  func asLedger(principal : Principal) : Ledger.Self { actor(debug_show(principal)) };

  // Fetches blocks from the ledger.
  // Can return fewer blocks than requested.
  func fetch(ledger : Ledger.Self, { start : Nat64; length : Nat64 }) : async [Ledger.Block] {
    let fetch_start = start;

    Prim.debugPrint("[PROXY]: fetching blocks " # debug_show start # ".." # debug_show (start + length));

    let result = await ledger.query_blocks({start = start; length = length});

    let len = do {
      var total = result.blocks.size();
      let archive = result.archived_blocks;
      for (j in range(0, archive.size())) total += Prim.nat64ToNat(archive[j].length);
      total
    };

    let buf : [var ?Ledger.Block] = Prim.Array_init(len, null);

    assert fetch_start <= result.first_block_index;

    Prim.debugPrint("[PROXY]: received " # debug_show result.blocks.size() # " blocks from ledger");

    for (i in range(0, result.blocks.size())) {
      let idx = Prim.nat64ToNat(result.first_block_index - fetch_start) + i;
      Prim.debugPrint("[PROXY] block #" # debug_show idx # ": " # debug_show result.blocks[i]);
      buf[idx] := ?result.blocks[i];
    };

    Prim.debugPrint("[PROXY]: fetching from " # debug_show result.archived_blocks.size() # " archives");

    for (j in range(0, result.archived_blocks.size())) {
      Prim.debugPrint("[PROXY]: fetching from archive " # debug_show j);

      let {start; length; callback} = result.archived_blocks[j];
      assert fetch_start <= start;

      var fetch_from = start;

      while (fetch_from < (start + length)) {
        let fetch_len = length - (fetch_from - start);

        Prim.debugPrint("[PROXY]: fetching blocks " # debug_show start # ".." # debug_show (fetch_from + fetch_len));
        switch (await callback({ start = fetch_from; length = fetch_len })) {
          case (#Ok ({ blocks })) {
            for (i in range(0, blocks.size())) {
              let idx = Prim.nat64ToNat(start - fetch_start) + i;
              Prim.debugPrint("[PROXY] block #" # debug_show idx # ": " # debug_show blocks[i]);
              buf[idx] := ?blocks[i];
            };
            fetch_from += Prim.natToNat64(blocks.size());
          };

          case (#Err e) {
            throw Prim.error(debug_show(e));
          };
        };
      };
    };

    Prim.Array_tabulate(buf.size(), func(i: Nat) : Ledger.Block {
      switch (buf[i]) {
        case (?x) { x };
        case null { assert false; loop {} }
      }
    })

  };

  private class range(x : Nat, y : Int) {
    var i = x;
    public func next() : ?Nat { if (i >= y) { null } else {let j = i; i += 1; ?j} };
  }; 
}
