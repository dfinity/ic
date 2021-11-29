# nix-shell environment for working on DFINITY's Rust packages.
{ system ? builtins.currentSystem
, pkgs ? import ../nix { inherit system; }
}:

(import ./default.nix { inherit pkgs; }).shell
