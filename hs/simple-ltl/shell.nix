# nix-shell environment for working on DFINITY's Haskell packages.
{ system ? builtins.currentSystem
, config ? {}
, overlays ? []
, crossSystem ? null
, pkgs ? import ../../nix { inherit system config overlays crossSystem; }
, rs ? import ../../rs { inherit pkgs; }
}:

(import ../default.nix { inherit pkgs rs; }).simple-ltl-shell
