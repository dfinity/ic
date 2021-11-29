{ pkgs ? import <nixpkgs> {} }:

with pkgs;

stdenv.mkDerivation {
  name = "shell";

  buildInputs = [ bash ];

  shellHook = ''
    export NIX_PATH="nixpkgs=${toString <nixpkgs>}"
  '';
}
