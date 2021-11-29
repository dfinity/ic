{ pkgs ? import ../nix { inherit system; }
, system ? builtins.currentSystem
, rs ? import ../rs { inherit pkgs; }
}:
(import ./shell.nix { inherit pkgs system; }).overrideAttrs (
  original: {
    buildInputs = original.buildInputs
    ++ [
      rs.ic-cup-explorer
      rs.ic-admin
      rs.ic-replay
      rs.ic-consensus-pool-util
      rs.ic-crypto-csp
      rs.ic-regedit
      rs.ic-workload-generator
      rs.state-tool
    ];
  }
)
