{ pkgs ? import ../nix { inherit system; }
, system ? builtins.currentSystem
}:
let
  python3-packages = python-packages: with python-packages; (
    [
      GitPython
      PyGithub
      dateutil
      elasticsearch
      elasticsearch-dsl
      freezegun
      jsonschema
      junit-xml
      mypy
      pre-commit
      pyjson5
      pylint
      pytest
      pytest-shutil
      python-gitlab
      pyyaml
      toml
      xmltodict
    ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
      # requires gfortran via numpy, not cached on macos
      black
    ]
  );
  python3-with-packages = pkgs.python3.withPackages python3-packages;
in
pkgs.mkCiShell {
  buildInputs = [
    pkgs.buf
    pkgs.binutils # Provides objcopy, used to strip symbols from binaries.
    pkgs.shfmt
    pkgs.shellcheck
    python3-with-packages
  ];
  PYTHONPATH = builtins.toString ./src;
}
