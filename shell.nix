{ pkgs ? import ./nix { inherit system; }
, system ? builtins.currentSystem
, rs ? import ./rs { inherit pkgs; }
, prod ? import ./testnet { inherit pkgs; }
, docs ? import ./docs { inherit pkgs; }
}:
pkgs.mkCompositeShell {
  buildInputs = [
    # These are used in pre-commit.
    pkgs.ansible-lint
    pkgs.nixpkgs-fmt
    pkgs.shfmt
    pkgs.rustfmt
    pkgs.buf
    pkgs.pre-commit
  ];
}
