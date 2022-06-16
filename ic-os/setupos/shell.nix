{ pkgs ? import ../../nix { inherit system; }
, system ? builtins.currentSystem
}:
let
  python3-packages = python-packages: [];
  python3-with-packages = pkgs.python3.withPackages python3-packages;
in
pkgs.mkCiShell {
  buildInputs = [
    pkgs.dosfstools
    pkgs.fakeroot
    pkgs.libtar
    pkgs.mtools
    pkgs.policycoreutils
    python3-with-packages
  ];
}
