{ system ? builtins.currentSystem
, pkgs ? import ../nix { inherit system; }
, src ? builtins.fetchGit ../.
}:

with pkgs.lib;

# This file collects all the crates in the "debug" workspace, runs clippy, cargo fmt, and puts all
# the produced binaries in $out/bin (so that the dependency report can check their contents).
let
  # clippy directly uses librustc, so our regular rustc wrapper is ignored.
  # this either should be moved into cargo2nix or i should expose the cargo2nix wrapper
  # function somewhere ergonomically.
  clippyWrapper = pkgs.runCommandNoCC "clippy-wrapper"
    {
      inherit (pkgs.stdenv) shell;
      exename = "clippy-driver";
      rustc = pkgs.clippy;
      utils = "${../nix/overlays/cargo2nix}/overlay/utils.sh";
    } ''
    mkdir -p $out/bin
    substituteAll ${../nix/overlays/cargo2nix}/overlay/wrapper.sh $out/bin/$exename
    chmod +x $out/bin/$exename
    # cargo-clippy runs 'exec $(dirname $0)/clippy-driver' so they need to be in the same place
    cp ${pkgs.clippy}/bin/cargo-clippy $out/bin
  '';

  lintCrate = drv:
    let
      disallowedLints = [ "warnings" "clippy::all" "clippy::mem_forget" ];
      lintLine = pkgs.lib.concatMapStringsSep " " (l: "-D ${l}") disallowedLints;
    in
      {
        name = "lint-${drv.name}-${drv.version}";
        nativeBuildInputs = drv.nativeBuildInputs ++ [ pkgs.rustfmt clippyWrapper ];
        runCargo = ''
          ln -s ${./rustfmt.toml} rustfmt.toml
          cargo fmt --all -- --check
          cargo clippy $CARGO_VERBOSE --tests --benches -- ${lintLine} -C debug-assertions=on
          cargo clippy $CARGO_VERBOSE --tests --benches -- ${lintLine} -C debug-assertions=off
        '';
        installCheckPhase = ''
          mkdir -p $out
        '';
      };

  disabled-tests = [
    # Ledger canister test now only runs on GitLab.
    "ledger-canister"
  ];

  runTests = run_slow: drv:
    if builtins.elem drv.name disabled-tests then null else
      (
        drv.override {
          extraTestFlags = _: if run_slow then [ "slowtest" ] else [ "--skip" "slowtest" ];
        }
      ).overrideDerivation (
        attrs: {
          LD = "${pkgs.stdenv.cc}/bin/ld";
          CARGO_PKG_NAME = drv.name;
          CARGO_MANIFEST_DIR = drv.src;
          IN_NIX_TEST = 1;
          RUST_BACKTRACE = 1;
          nativeBuildInputs =
            attrs.nativeBuildInputs
            ++ optionals (drv.name == "ic-scenario-tests" || drv.name == "ic-rosetta-api")
              [ pkgs.dfinity-rs.nodemanager.release pkgs.dfinity-rs.ic-replica.release ]
            ++ optionals (drv.name == "ic-rosetta-api") [ pkgs.rosetta-cli ];
        } // addCanisterBins drv.name
      );

  runBenchmarks = drv:
    drv.overrideDerivation
      (
        attrs:
          {
            LD = "${pkgs.stdenv.cc}/bin/ld";
            CARGO_PKG_NAME = drv.name;
            CARGO_MANIFEST_DIR = drv.src;
            IN_NIX_TEST = 1;
            RUST_BACKTRACE = 1;
            nativeBuildInputs = attrs.nativeBuildInputs ++ [ pkgs.gnuplot ];
            # Benchmarks results of the master jobset are uploaded to
            # ElasticSearch. So we need to run those benchmarks on a dedicated and
            # idle builder to minimise noise in the results. However for PRs we
            # don't mind if benchmarks are run on regular builders. So we only
            # require the "benchmark" feature for builds on master to not cause a
            # queue of PR builds to form before the benchmark builder. In case an
            # engineer is interested in running the benchmarks of a PR on the dedicated
            # builder he can label the PR with `ci-run-benchmarks-on-dedicated-builder`.
            #
            # Note we don't require the `benchmark` feature for darwin builds
            # due to the fact that we have limited darwin builder capacity and
            # we don't want to take out a builder to act as a dedicated
            # benchmarker.
            requiredSystemFeatures =
              pkgs.lib.optional (!pkgs.stdenv.isDarwin && (pkgs.isMaster || (pkgs.labels.ci-run-benchmarks-on-dedicated-builder or false))) [
                "benchmark"
              ];
          } // addCanisterBins drv.name // {
            doDist = true;
            distPhase = ''
              rm -rf $out
              mkdir -p $out/$CARGO_PKG_NAME
              if [ -d target/criterion ]; then
                cp -R target/criterion $out/$CARGO_PKG_NAME
              fi
            '';
          }
      );

  addCanisterBins = name:
    listToAttrs (
      map
        (
          bin_:
            let
              bin = bin_.bin or bin_;
              crate = bin_.crate or name;
            in
              {
                name = toUpper (replaceStrings [ "-" ] [ "_" ] "${bin}_WASM_PATH");
                value = pkgs.runCommand "${bin}_opt.wasm" {} ''
                  ${pkgs.ic-cdk-optimizer}/bin/ic-cdk-optimizer \
                    "${pkgs.dfinity-rs-wasm.${crate}.release}/bin/${bin}.wasm" \
                    --output $out --wasm-opt-path ${pkgs.binaryen}/bin/wasm-opt
                '';
              }
        )
        (canistersForTests.${name} or [])
    );

  # If you add a new test that depends on loading a rust canister, please add the crate name and binary name to this list.
  # You can find these tests by searching for usages of the method `Project::cargo_bin`.
  canistersForTests = {
    rust-canister-tests = [ "json" "nan_canonicalized" "panics" "stable" "time" "inter_canister_error_handling" ];
    pmap = [ "pmap_canister" ];
    big-map = [ "bigmap_index" "bigmap_data_bucket" ];
    dfn_candid = [ "candid-test-canister" ];
    dfn_core = [ "wasm" ];
    registry-canister = [
      "registry-canister"
      {
        bin = "cycles-minting-canister";
        crate = "cycles-minting-canister";
      }
    ];
    ic-nns-governance = [ "governance-canister" ];
    ic-scenario-tests = nnsCanisters ++ [
      {
        bin = "xnet-test-canister";
        crate = "xnet-test";
      }
      {
        bin = "wasm";
        crate = "dfn_core";
      }
    ];
    ic-nns-integration-tests = nnsCanisters ++ [
      {
        bin = "governance-mem-test-canister";
        crate = "ic-nns-integration-tests";
      }
      {
        bin = "mem-utils-test-canister";
        crate = "ic-nns-integration-tests";
      }
      {
        bin = "ledger-archive-node-canister";
        crate = "ledger-canister";
      }
    ];
    ledger-canister = [
      "ledger-canister"
      {
        bin = "ledger-archive-node-canister";
        crate = "ledger-canister";
      }
      {
        bin = "test-notified";
        crate = "ledger-canister";
      }
    ];
    ic-nns-handler-root = [
      "root-canister"
      "upgrade-test-canister"
      {
        bin = "registry-canister";
        crate = "registry-canister";
      }
    ];
    cycles_transfer = [ "alice" "bob" ];
    statesync-test = [ "statesync-test-canister" ];
    xnet-test = [ "xnet-test-canister" ];
    ic-nns-gtc = [ "genesis-token-canister" ];
    ic-nns-rewards = [ "rewards-canister" ];
    ic-rosetta-api = [
      {
        bin = "ledger-canister";
        crate = "ledger-canister";
      }
    ];
  };

  nnsCanisters = [
    {
      bin = "registry-canister";
      crate = "registry-canister";
    }
    {
      bin = "governance-canister";
      crate = "ic-nns-governance";
    }
    {
      bin = "ledger-canister";
      crate = "ledger-canister";
    }
    {
      bin = "root-canister";
      crate = "ic-nns-handler-root";
    }
    {
      bin = "cycles-minting-canister";
      crate = "cycles-minting-canister";
    }
    {
      bin = "genesis-token-canister";
      crate = "ic-nns-gtc";
    }
    {
      bin = "identity-canister";
      crate = "identity-canister";
    }
    {
      bin = "nns-ui-canister";
      crate = "nns-ui-canister";
    }
  ];

  # we want to aggregate all the [lint,test,bench] jobs together in one derivation, but it should also be trivial for a dev to run `nix-build rs -A run-tests.$some-crate`.
  buildEnvWithPassthru = attrs: crates: pkgs.buildEnv
    (
      attrs // {
        passthru = crates;
        paths = attrValues crates;
      }
    );

  # We run tests of the release builds of our crates by default. However some
  # crates fail in release mode so we use debug mode for them instead.
  testOf = c:
    if builtins.elem c.test_release.name [
      # TODO: The tests of the ic-execution-environment crate fail when build in release mode with the following errors:
      #
      #   fatal runtime error: fatal runtime error: failed to initiate panic, error failed to initiate panic, error 55
      #
      #   fatal runtime error: fatal runtime error: fatal runtime error: error: test failed, to rerun pass '--test lucet-tests'
      #
      #   Caused by:
      #     process didn't exit successfully: `/build/source/target/x86_64-unknown-linux-gnu/release/deps/lucet_tests-6de6f07159868fa0 --skip slowtest` (signal: 6, SIGABRT: process abort signal)
      #
      # This is tracked in https://dfinity.atlassian.net/browse/EXE-125.
      #
      # So we test the debug build instead:
      "ic-execution-environment"
    ]
    then c.test else c.test_release;

in
{
  lint =
    buildEnvWithPassthru
      {
        name = "dfinity-rs-lint";
        pathsToLink = [ "/empty" ];
      }
      (pkgs.dfinity-foreach-crate-native (c: c.test.overrideDerivation lintCrate));

  rust-workspace-doc = pkgs.documentWorkspace (pkgs.dfinity-foreach-crate-native (c: c.debug));

  tests = buildEnvWithPassthru { name = "dfinity-rs-tests"; } (
    pkgs.dfinity-foreach-crate (c: runTests false (testOf c))
  );

  tests_slow = pkgs.lib.allowFailureOnPrs (
    buildEnvWithPassthru { name = "dfinity-rs-tests-slow"; } (
      pkgs.dfinity-foreach-crate (c: runTests true (testOf c))
    )
  );

  benchmarks = pkgs.lib.runBenchmarks {
    results = buildEnvWithPassthru
      {
        name = "dfinity-rs-benches";
        postBuild = ''
          date --utc --iso-8601=seconds > $out/timestamp
        '';
        # lib.runBenchmarks searches directories called "target" for results
        extraPrefix = "/target";
      }
      (pkgs.dfinity-foreach-crate (x: runBenchmarks x.bench));
    inherit src;
    name = "workspace";
  };
}
