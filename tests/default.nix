{ pkgs ? import ../nix { inherit system; }
, system ? builtins.currentSystem
, rs ? import ../rs { inherit pkgs; }
, verbose ? pkgs.labels.ci-log-trace or (! pkgs.lib.isHydra) # no need for extra jobs on Hydra
}:
{
  drun-test = import ./drun { inherit pkgs rs; };
  ic-ref-test = import ./ic-ref-test { inherit pkgs rs; };
  ic-workloadgen-test = import ./ic-workloadgen-test { inherit pkgs verbose; };

  shell = pkgs.mkShell {
    nativeBuildInputs = [
      pkgs.ic-ref

      # For the API integration tests
      pkgs.netcat-gnu

      # same tools for linux and darwin
      pkgs.coreutils

      # for tmux-testnet
      pkgs.tmux
      pkgs.jq
      pkgs.nc

      # We rely on openssl, so good to have it in the shell as well
      pkgs.openssl
    ] ++ # dsymutil is needed to produce debug objects
    pkgs.lib.optional pkgs.stdenv.isDarwin pkgs.stdenv.cc.bintools;
  };
}
