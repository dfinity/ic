# nix-shell environment for working on DFINITY's Rust packages.
{ pkgs ? import ../../nix {
    overlays = [ (import ../nix/overlays/experimental.nix) ];
  }
, rs ? import ../../rs { inherit pkgs; }
}:
pkgs.mkCiShell {
  name = "dfinity-experimental-rust-workspace";
  inputsFrom = [ rs.shell ];
  nativeBuildInputs = with pkgs; [
    # experimental.wasm-c-api
    # experimental.wasm-c-api.dev
    libsigsegv
  ];
}
