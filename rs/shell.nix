{ system ? builtins.currentSystem
, pkgs ? import ../nix { inherit system; }
}:

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
).overrideAttrs crateEnv
