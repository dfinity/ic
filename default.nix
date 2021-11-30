{ system ? builtins.currentSystem
, pkgs ? import ./nix { inherit system config overlays crossSystem isMaster labels; }
, jobset ? import ./ci/ci.nix { inherit system RustSec-advisory-db isMaster labels src pkgs; }
, config ? {}
, overlays ? []
, crossSystem ? null
, isMaster ? true
, labels ? {}
  # we check for the existence of ".git" before callin fetchGit because otherwise
  # Nix fails if this isn't a Git checkout. Note that worktrees _do_ contain a
  # `.git`.
, src ? if builtins.readDir ./. ? ".git" then builtins.fetchGit ./. else ./.
  # The RustSec advisory-db is a dependency of the ic.rs.cargo-security-audit
  # job defined in ./rs/default.nix. It's passed here as an argument so that we
  # can configure it as a jobset input on Hydra. This has the advantage that
  # whenever a new security vulnerability is published this input is updated
  # causing the cargo-security-audit job to run.
, RustSec-advisory-db ? null
}:
let
  baseJobs =
    if src ? mergeBase
    then import src.mergeBase { inherit system; src = src.mergeBase; }
    else null;
  rs = import ./rs { inherit pkgs src RustSec-advisory-db; };
  prod = import ./testnet { inherit pkgs rs baseJobs jobset; };

  rs-required = rs // pkgs.lib.requireAllLinuxAndDarwin {
    inherit (rs) shell;
  };
in
rec {
  ic = rec {
    rs = rs-required;
    tests = import ./tests { inherit pkgs rs; };

    # This is to make sure CI evaluates the top-level shell derivation,
    # build its dependencies and populate the hydra cache with the
    # dependencies.
    shell = pkgs.lib.requireLinuxAndDarwin (import ./shell.nix { inherit pkgs rs prod; });

    inherit prod;
  };

  # This gives other repositories direct stable access to certain
  # derivations, so that we can change the internal structure without
  # breaking their import
  drun = ic.rs.drun-unwrapped;

  upload_replica_benchmarks = ic.rs.benchmarks.upload;

  publish.ic = import ./publish.nix { inherit pkgs jobset; inherit (src) rev; };

}
