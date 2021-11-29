{ system ? builtins.currentSystem
, pkgs ? import ../nix { inherit system; }
, rs ? import ../rs { inherit pkgs; }
, baseJobs ? null
, jobset ? import ../ci/ci.nix { inherit system pkgs; }
}:
let
  tools = import ./tools { inherit system pkgs rs jobset; };
in
{
  # A NixOS test that checks if a small network of IC-OS nodes boots up correctly.
  tests = import ./tests { inherit system pkgs rs tools baseJobs jobset; };
  shell = import ./shell.nix { inherit pkgs; };
}
