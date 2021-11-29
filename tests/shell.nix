# nix-shell environment for working on DFINITY's system tests.
{ system ? builtins.currentSystem
, pkgs ? import ../nix { inherit system; }
}:

(import ./default.nix { inherit pkgs; }).shell
