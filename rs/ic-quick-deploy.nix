{ system ? builtins.currentSystem
, pkgs ? import ../nix { inherit system config overlays crossSystem; }
, config ? {}
, overlays ? []
, crossSystem ? null
, src ? builtins.fetchGit ../.
}:
# The goal of this expression is to produce jobs that are to be run on a particular
# branch in order to get the binaries faster to the testnet, by not building everything.
let
  rs = import ./. { inherit pkgs src; doCheck = false; };
in
{
  ic-quick-deploy = {
    ic-replica = rs.ic-replica;
    nodemanager = rs.nodemanager;
    ic-prep = rs.ic-prep;
    # These jobs are needed here so they'd push changes to blobules
    ic-replica-release = rs.ic-replica-release;
    nodemanager-release = rs.nodemanager-release;
    ic-prep-release = rs.ic-prep-release;
    ic-admin-release = rs.ic-admin-release;
    ic-workload-generator-release = rs.ic-workload-generator-release;
    ic-registry-canister-release = rs.ic-registry-canister-release;
    ic-state-tool-release = rs.ic-state-tool-release;
    e2e-test-driver-release = rs.e2e-test-driver-release;
    statesync-test-canister-release = rs.statesync-test-canister-release;
    xnet-test-canister-release = rs.xnet-test-canister-release;
  };
}
