# nix-shell environment for working on Rust packages.
{ pkgs ? import ../nix {
    overlays = [ (import nix/overlays/experimental.nix) ];
  }
, rs ? import ../../rs { inherit pkgs; }
}@args:
pkgs.mkCiShell {
  inputsFrom = [
    (import ./rs/shell.nix args)
  ];
}
