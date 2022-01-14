{ pkgs ? import <nixpkgs> {} }:
let
  python = pkgs.python38.withPackages (p: with p; [ pandas ]);
in
pkgs.mkShell { buildInputs = [ python ]; }
