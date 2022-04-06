{ system ? builtins.currentSystem
, pkgs ? import ../nix { inherit system; }
}:

let
  crateEnv = import ./crate-environment.nix { inherit pkgs; };

  honeycomb-beeline =
    with pkgs.python3Packages;
    buildPythonPackage rec {
      pname = "honeycomb-beeline";
      version = "3.2.0";

      src = fetchPypi {
        inherit pname version;
        sha256 = "1aaxqp6d0dlg7yxzm602v9lv8rzlias625q542i45i3sw541bdxs";
      };

      # check phase depends on a bunch of commonly used python web frameworks
      doCheck = false;

      propagatedBuildInputs = [
        wrapt
        libhoney
      ];
    };

  libhoney =
    with pkgs.python3Packages;
    buildPythonPackage rec {
      pname = "libhoney";
      version = "2.0.0";

      src = fetchPypi {
        inherit pname version;
        sha256 = "0i0s4lqpn04d2sm97llhanrpcljzygpr920kiynxahyqjfyk8qwy";
      };

      propagatedBuildInputs = [
        mock
        requests-mock
        requests
        six
        statsd
        tornado
      ];
    };
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

        pkgs.nix-prefetch-git

        # useful cargo utilities
        pkgs.cargo-flamegraph
        pkgs.cargo-expand

        # used by rosetta-api
        pkgs.rosetta-cli

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

        # For creating IC-OS config images and universal VM config images
        # (./tests/create-universal-vm-config-image.sh)
        pkgs.dosfstools
        pkgs.mtools
        pkgs.zstd
      ]
      ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
        # provides the `taskset` command, which we use to fix core affinity in the shell
        pkgs.utillinux
        pkgs.libselinux
        pkgs.libunwind

        # this tool is used by cargo-flamegraph
        pkgs.linuxPackages.perf

        # A rust code-coverage tool: https://github.com/xd009642/tarpaulin
        pkgs.cargo-tarpaulin

        # dependencies for coverage.py
        pkgs.kcov
        pkgs.python3Packages.toml
      ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
        # used for honeycomb traces in CI scripts
        honeycomb-beeline
      ];

      buildInputs = [
        # Needed by gitlab-ci/src/test_results/summary.py
        pkgs.python3Packages.termcolor
        pkgs.python3Packages.requests
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

          if ! hash rustup 2>/dev/null; then
            echo >&2 "Warning: The IC nix-shell no longer provides rustc. Please install rustup using the instructions at https://rustup.rs/."
          fi
        '';
    }
  )
).overrideAttrs crateEnv
