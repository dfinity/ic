{ pkgs ? import ../nix { inherit system; }
, system ? builtins.currentSystem
}:
pkgs.mkCiShell {

  buildInputs = [
    pkgs.python3
    pkgs.rsync
    pkgs.mypy
    pkgs.pre-commit
  ];
}
