{ system ? builtins.currentSystem
, pkgs ? import ../nix { inherit system; }
, RustSec-advisory-db ? null
, src ? builtins.fetchGit ../.

  # TODO: cargo tests are currently flaky on Darwin. So we temporarily disable them on
  # that platform. Re-enable them again when the following is fixed:
  # https://dfinity.atlassian.net/browse/DFN-1605
, doCheck ? !pkgs.stdenv.isDarwin
}:

let
  lib = pkgs.lib;
  mkReleaseMultifile = pkgs.callPackage ./mk-release.nix {};
  mkRelease = rname: version: package: what:
    mkReleaseMultifile rname version [ { inherit package; infile = "bin/${what}"; outfile = null; } ];

  inherit (pkgs.stdenv) isDarwin isLinux;

  # Wraps 'mkRelease' and reads as much information as possible from the
  # Cargo.toml, in particular: name, version, exename.
  # This version appends the 'decoration' to the name of the artifact.
  releaseCrateDecorated = drv: cratePath: crateName: decoration:
    let
      crateInfo = builtins.fromTOML (builtins.readFile (cratePath + "/Cargo.toml"));
      crateBin =
        if builtins.hasAttr "bin" crateInfo && builtins.length crateInfo.bin == 1
        then (pkgs.lib.head crateInfo.bin).name
        else if ! builtins.hasAttr "bin" crateInfo
        then crateName
        else
          abort
            "cannot read crate executable name from ${builtins.toJSON crateInfo.bin} for ${crateName}";
    in
      mkRelease (crateInfo.package.name + decoration) crateInfo.package.version drv crateBin;

  # Plain version of the above, without any decorations.
  releaseCrate = drv: crateName:
    releaseCrateDecorated drv (./. + "/${crateName}") crateName "";

  standalone = workspace: name: lib.standaloneRust {
    drv = workspace;
    exename = name;
    usePackager = false;
  };

  copyBin = drv: name: pkgs.runCommandNoCC name {} ''
    mkdir -p $out/bin
    cp ${drv}/bin/${name} $out/bin
  '';

  workspace = pkgs.dfinity-rs;
in

rec {

  inherit (import ./check.nix { inherit system pkgs src; })
    lint tests tests_slow benchmarks rust-workspace-doc
    ;

  ic-replica = standalone workspace.ic-replica.release "replica";
  ic-replica-debug = standalone workspace.ic-replica.debug "replica";
  ic-replica-with-symbols = standalone pkgs.dfinity-rs-with-symbols.ic-replica.release "replica";

  nodemanager = standalone workspace.nodemanager.release "nodemanager";

  boundary-node-control-plane = standalone workspace.boundary-node-control-plane.release "boundary-node-control-plane";

  state-tool = workspace.ic-state-tool.release;

  # copy only the binaries so that we don't drag .rlib files with a huge closure around
  ic-replica-unwrapped = copyBin workspace.ic-replica.release "replica";
  drun-unwrapped = copyBin workspace.ic-drun.release "drun";
  nodemanager-unwrapped = copyBin workspace.nodemanager.release "nodemanager";
  ic-starter-unwrapped = copyBin workspace.ic-starter.release "ic-starter";
  ic-admin-unwrapped = copyBin workspace.ic-admin.release "ic-admin";

  drun = standalone workspace.ic-drun.release "drun";
  ic-consensus-pool-util = standalone workspace.ic-artifact-pool.release "ic-consensus-pool-util";
  instrument-wasm = standalone workspace.ic-wasm-utils.release "instrument-wasm";
  ic-crypto = standalone workspace.ic-crypto.release "crypto";
  ic-crypto-csp = standalone workspace.ic-crypto.release "ic-crypto-csp";
  ic-crypto-debug = standalone workspace.ic-crypto.debug "crypto";
  ic-starter = standalone workspace.ic-starter.release "ic-starter";
  ic-prep = standalone workspace.ic-prep.release "ic-prep";
  ic-principal-id = standalone workspace.ic-prep.release "ic-principal-id";
  ic-admin = standalone workspace.ic-admin.release "ic-admin";
  ic-identity = standalone workspace.ic-identity.release "ic-identity";
  ic-p8s-service-discovery = standalone workspace.ic-p8s-service-discovery.release "ic-p8s-service-discovery";
  ic-workload-generator = standalone workspace.ic-workload-generator.release "ic-workload-generator";
  ic-nns-init = standalone workspace.ic-nns-init.release "ic-nns-init";
  ic-cup-explorer = standalone workspace.ic-cup-explorer.release "ic-cup-explorer";
  ic-replay = standalone workspace.ic-replay.release "ic-replay";
  ic-regedit = standalone workspace.ic-regedit.release "ic-regedit";

  e2e-test-driver = standalone workspace.ic-scenario-tests.release "e2e-test-driver";
  ic-test-bin = workspace.tests.release;
  ic-replica-release = releaseCrate ic-replica "replica";
  ic-replica-with-symbols-release = releaseCrateDecorated ic-replica-with-symbols ./replica "replica" "-with-symbols";

  nodemanager-release = releaseCrate nodemanager "nodemanager";
  boundary-node-control-plane-release = releaseCrateDecorated boundary-node-control-plane ./boundary_node/control_plane "boundary-node-control-plane" "";

  drun-release = releaseCrate drun "drun";
  ic-prep-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./prep/Cargo.toml);
    in
      mkRelease "ic-prep" crateInfo.package.version ic-prep "ic-prep";
  ic-principal-id-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./prep/Cargo.toml);
    in
      mkRelease "ic-principal-id" crateInfo.package.version ic-principal-id "ic-principal-id";
  ic-workload-generator-release = releaseCrate ic-workload-generator "workload_generator";

  ic-admin-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./prep/Cargo.toml);
      drv = mkRelease "ic-admin" crateInfo.package.version ic-admin "ic-admin";
    in
      # because ic-admin is needed during deploy we make sure that it is built
      # on both Darwin and Linux.
      pkgs.lib.requireLinuxAndDarwin drv;

  ic-cup-explorer-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./prep/Cargo.toml);
    in
      mkRelease "ic-cup-explorer" crateInfo.package.version ic-cup-explorer "ic-cup-explorer";

  ic-identity-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./identity/Cargo.toml);
    in
      mkRelease "ic-identity" crateInfo.package.version ic-identity "ic-identity";

  ic-p8s-service-discovery-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./ic_p8s_service_discovery/Cargo.toml);
    in
      mkRelease "ic-p8s-service-discovery" crateInfo.package.version ic-p8s-service-discovery "ic-p8s-service-discovery";

  registry-canister = standalone pkgs.dfinity-rs-wasm.registry-canister "registry-canister.wasm";

  registry-canister-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./registry/canister/Cargo.toml);
    in
      mkRelease "registry-canister" crateInfo.package.version
        pkgs.dfinity-rs-wasm.registry-canister "registry-canister.wasm";

  ic-nns-governance-canister-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./nns/governance/Cargo.toml);
    in
      mkRelease "ic-nns-governance-canister" crateInfo.package.version
        pkgs.dfinity-rs-wasm.ic-nns-governance "governance-canister.wasm";

  ic-nns-handler-root-canister-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./nns/handlers/root/Cargo.toml);
    in
      mkRelease "ic-nns-handler-root-canister" crateInfo.package.version
        pkgs.dfinity-rs-wasm.ic-nns-handler-root "root-canister.wasm";

  ic-nns-handler-lifeline-canister = workspace.lifeline.release;
  ic-nns-handler-lifeline-canister-release = mkRelease "ic-nns-handler-lifeline-canister" "0.0.0"
    ic-nns-handler-lifeline-canister "lifeline.wasm";

  ic-nns-genesis-token-canister-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./nns/gtc/Cargo.toml);
    in
      mkRelease "ic-nns-genesis-token-canister" crateInfo.package.version
        pkgs.dfinity-rs-wasm.ic-nns-gtc "genesis-token-canister.wasm";

  ledger-canister-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./rosetta-api/Cargo.toml);
    in
      mkRelease "ledger-canister" crateInfo.package.version
        pkgs.dfinity-rs-wasm.ledger-canister "ledger-canister.wasm";

  # This is a bundle containing all nns canisters, their candid files, and the canister_ids.json file
  ic-nns-bundle-release = mkReleaseMultifile "ic-nns-bundle" "0.0.0" (
    let
      copyFile = package: { inherit package; infile = null; outfile = builtins.baseNameOf package; };
    in
      [
        { package = pkgs.dfinity-rs-wasm.registry-canister; infile = "bin/registry-canister.wasm"; outfile = null; }
        { package = pkgs.dfinity-rs-wasm.ic-nns-governance; infile = "bin/governance-canister.wasm"; outfile = null; }
        { package = pkgs.dfinity-rs-wasm.ic-nns-handler-root; infile = "bin/root-canister.wasm"; outfile = null; }
        { package = ic-nns-handler-lifeline-canister; infile = "bin/lifeline.wasm"; outfile = null; }
        { package = pkgs.dfinity-rs-wasm.ic-nns-gtc; infile = "bin/genesis-token-canister.wasm"; outfile = null; }
        { package = pkgs.dfinity-rs-wasm.ledger-canister; infile = "bin/ledger-canister.wasm"; outfile = null; }
        { package = pkgs.dfinity-rs-wasm.cycles-minting-canister; infile = "bin/cycles-minting-canister.wasm"; outfile = null; }
        { package = pkgs.dfinity-rs-wasm.identity-canister; infile = "bin/identity-canister.wasm"; outfile = null; }
        { package = pkgs.dfinity-rs-wasm.nns-ui-canister; infile = "bin/nns-ui-canister.wasm"; outfile = null; }
        (copyFile ./nns/canister_ids.json)
        (copyFile ./nns/handlers/lifeline/lifeline.did)
        (copyFile ./nns/handlers/root/canister/root.did)
        (copyFile ./nns/governance/canister/governance.did)
      ]
  );

  ic-nns-init-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./nns/init/Cargo.toml);
    in
      mkRelease "ic-nns-init" crateInfo.package.version ic-nns-init "ic-nns-init";

  e2e-test-driver-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./scenario_tests/Cargo.toml);
    in
      mkRelease "ic-scenario-tests" crateInfo.package.version e2e-test-driver "e2e-test-driver";

  statesync-test-canister-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./rust_canisters/statesync_test/Cargo.toml);
    in
      mkRelease "statesync-test-canister" crateInfo.package.version
        pkgs.dfinity-rs-wasm.statesync-test "statesync-test-canister.wasm";

  xnet-test-canister-release =
    let
      crateInfo = builtins.fromTOML (builtins.readFile ./rust_canisters/xnet_test/Cargo.toml);
    in
      mkRelease "xnet-test-canister" crateInfo.package.version
        pkgs.dfinity-rs-wasm.xnet-test "xnet-test-canister.wasm";

  shell =
    let
      rustdocs = pkgs.lib.writeCheckedShellScriptBin "rustdocs" [] ''
        doc=''${1:-std}
        file="${pkgs.rustc.doc}/share/doc/rust/html/$doc/index.html"
        if [[ -f "$file" ]]; then
            exec ${pkgs.xdg_utils}/bin/xdg-open "$file"
        fi
        echo "$doc Rust documentation not found"
        exit 1
      '';

      # We need to apply special linker flags when compiling the binaries listed in ./shared-crates.
      # Setting of these flags is done using a wrapper around rustc which we define here
      # and put in the PATH below.
      rustc = pkgs.rustBuilder.rustLib.wrapRustc {
        inherit (pkgs) rustc;
        exename = "rustc";
      };
      rustdoc = pkgs.rustBuilder.rustLib.wrapRustc {
        inherit (pkgs) rustc;
        exename = "rustdoc";
      };
      crateEnv = import ./crate-environment.nix { inherit pkgs; };
    in
      (
        pkgs.mkShell (
          {
            nobuildPhase = ''
              echo
              echo "This derivation is not meant to be built, aborting";
              echo
              touch $out
            '';

            nativeBuildInputs = [
              # same tools for linux and darwin
              pkgs.coreutils
              pkgs.nc

              # for vulnerability audit
              pkgs.cargo-audit
              pkgs.gnuplot

              pkgs.jo
              rustdocs

              pkgs.nix-prefetch-git

              pkgs.rustfmt
              pkgs.clippy
              pkgs.cargo-audit
              pkgs.rls
              pkgs.rust-analyzer
              pkgs.cargo-flamegraph
              pkgs.cargo-expand

              # used by rosetta-api
              pkgs.rosetta-cli

              # We bundle rustc and cargo and rustfmt because some tools (like intellij)
              # expect a "toolchain" containing all three.
              (
                pkgs.symlinkJoin {
                  name = "rust-toolchain";
                  paths = [ rustc pkgs.cargo pkgs.rustfmt ];
                }
              )
              rustdoc

              # Protobuf conformance checking
              pkgs.buf

              # Third party package management
              pkgs.niv

              # For building Motoko canisters like nns/handlers/lifeline/lifeline.mo
              pkgs.moc

              # used by the ic-ref-tests
              pkgs.ic-ref

              # for minimizing wasm
              pkgs.wabt
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              # provides the `taskset` command, which we use to fix core affinity in the shell
              pkgs.utillinux

              # this tool is used by cargo-flamegraph
              pkgs.linuxPackages.perf

              # A rust code-coverage tool: https://github.com/xd009642/tarpaulin
              pkgs.cargo-tarpaulin
            ];

            RUST_SRC_PATH = pkgs.rustPlatform.rustcSrc;

            # Only applicable to nix-shell users, remember to update the production value in:
            # ic-os/guestos/rootfs/etc/systemd/system/ic-replica.service
            RUST_MIN_STACK = 8192000;

            CARGO_BUILD_TARGET = pkgs.stdenv.hostPlatform.config;

            CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER = "${pkgs.llvmPackages_11.lld}/bin/lld";

            # Support up to 256 cores/threads
            shellHook =
              pkgs.lib.optionalString pkgs.stdenv.isLinux ''
                taskset -acp 0-255 $$
              '' + ''
                checkout_root=$(${pkgs.gitMinimal}/bin/git rev-parse --show-toplevel 2>/dev/null)
                if [ "$?" == 0 ]; then
                  source "$checkout_root/dshell/load"
                fi
                ulimit -n 8192
              '' + # We set CARGO_HOME different from ~/.cargo
              # to prevent bad interactions with other Rust installations (rustup).
              # We do set it to a central location to allow different
              # dfinity git worktrees to share the same cache.
              ''
                CARGO_HOME="''${CARGO_HOME:-"$HOME"/.cargo/dfinity}"
                export CARGO_HOME
              '';
          }
        )
      ).overrideAttrs crateEnv;

  # The following adds the dfinity.rs.cargo-security-audit job. This job will run
  # cargo-audit to scan our ./Cargo.lock file for any crates with published
  # security vulnerabilities. This job is run on a pinned advisory database on
  # PRs, and is also regularly run with the latest advisory database on master
  # (through an input to the `master` jobset in the hydra-jobset repo, such
  # that the job is re-evaluated whenever the upstream advisory database
  # changes).
  #
  # `cargo audit` can be run locally inside the nix-shell in ./rs.
  cargo-security-audit = lib.cargo-security-audit {
    name = "dfinity";
    cargoLock = ./Cargo.lock;
    db =
      if !isNull RustSec-advisory-db
      then RustSec-advisory-db
      else pkgs.sources.advisory-db;
    ignores = import ./ignored-vulnerabilities.nix;
  };

  cargo-generate = pkgs.runCommandNoCC "cargo-generate"
    {
      buildInputs = [ pkgs.cargo2nix pkgs.nix-prefetch-git ];
      srcDir = builtins.toString ./.;
      shellHook = ''
        cd $srcDir
        cargo2nix -f
        echo "All done!"
        exit
      '';
    } ''
    touch $out
  '';
}
