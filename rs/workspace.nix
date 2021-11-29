# This file adds our Rust workspace to the global package set.
# It makes it more ergonomic to add inter-workspace dependencies
# when overriding certain crates. For example, many of our crates
# require the `replica` binary to run their testsuite.
self: super: with self.lib; {
  rustBuilder = super.rustBuilder.overrideScope' (
    self_rs: super_rs: {
      rustLib = super_rs.rustLib // {
        fetchCrateGit = { url, name, version, rev }:
          let
            repo = builtins.fetchGit {
              inherit rev url;
              # This is a known issue in nix upstream, see https://github.com/NixOS/nix/issues/2431.
              # builtins.fetchGit doesn't know how to locate tree objects that aren't directly reachable
              # from origin/master.
              # If you add a new git dependency in Cargo.toml, and then run a Nix build, you might get
              # an error that looks like: "fatal: not a tree object: 01f5e794913a18494642b5f237bd76c054339d61".
              # In that case, add the ref (e.g. 01f5e79...) as a key here, with the corresponding
              # branch or tag name as the value.
              ref = if builtins.elem url
                [
                  "https://github.com/dfinity/agent-rs.git"
                  "https://github.com/dfinity/cdk-rs"
                  "git://github.com/dfinity/cdk-rs"
                ]
              then "main"
              else {
                "43fe1ba0c803766f86bbd90a335229b42833e68e" = "fix-remove-index-ordmap";
                "73b51950cfc4f438bb71acb213be05a5eb81d9f9" = "v0.6-deterministic";
                "770cb8194342b8d3f1237edafb378338de541891" = "v0.13.0-fix-names-of-libz-and-libbz2";
                "858e6f3805abb2cb86d11bc2c0d6e70fd61b71c4" = "v0.19.0";
                "63d5b919306ebecc00cd39090910d89c02dcda9b" = "main";
                "523e8cc7a75328c85a6a349023b26875f6af5ad6" = "fix-6-1-0";
                "82481b6e4957ea9d399c325ff49c794261a1aae0" = "v0.13.10+2439";
                "82acf2662049de7c74c15aa69406e208380838a4" = "fix-7-0-3";
                "91a37cc1c685864654dc4460026aad1150a6cdba" = "fix-7-0-4";
                "03c258337c387dbf559778ba3cb886d45ed46b24" = "fix-8-1-2";
                "79a4482af85b364a137affd5848ef534e88a4176" = "reproducible";
                "3b3326ca0bc3059acb27811dd5a7e0be1065a59d" = "dfinity/v0.27";
                "3e783d8eb46c3f28f4c43f882d9a11f35acb0dab" = "v0.21.4-v3-no-extensions";
              }.${rev} or "master";
            };
          in
            self.buildPackages.runCommandNoCC "find-crate-${name}-${version}" {
              nativeBuildInputs = [ self.buildPackages.jq self.buildPackages.remarshal ];
            } ''
              shopt -s globstar
              for f in ${repo}/**/Cargo.toml; do
                if [ "$(remarshal -if toml -of json "$f" | jq '.package.name == "${name}" and .package.version == "${version}"')" = "true" ]; then
                  cp -pr --no-preserve=all "''${f%/*}" $out
                  exit 0
                fi
              done

              echo Crate ${name}-${version} not found in ${url}
              exit 1
            '';
      };
      workspace = self_rs.mkIcWorkspace {
        cargoFile = ./Cargo.nix;
        crateOverrides =
          [
            (
              self_rs.rustLib.makeOverride {
                overrideAttrs = import ./crate-environment.nix { pkgs = self; };
              }
            )
          ] ++ import ./overrides.nix self;
      };
    }
  );

  dfinity-foreach-crate = self.dfinity-foreach-crate-helper self.dfinity-rs;

  dfinity-foreach-crate-native = self.dfinity-foreach-crate-helper self.dfinity-rs-native;

  # given a workspace and a function `f`, this produces
  #
  # {
  #    crateA = f <crateA derivation>;
  #    crateB = f <crateB derivation>;
  #    ...
  # }
  #
  # useful for generating the tests in check.nix, among other cases.
  # You can return `null` from `f` if you want the given crate to be excluded
  dfinity-foreach-crate-helper = crates: f: listToAttrs (
    filter (x: x != null) (
      mapAttrsToList (
        name: crate:
        # these things are not crates
          if builtins.elem name [ "shell" "cratesRelease" "cratesDebug" ] then null else
            let
              attrs = {
                inherit name;
                value = f crate;
              };
            in
              if attrs.value == null then null else attrs
      ) crates
    )
  );

  dfinity-rs-native = self.dfinity-rs;

  dfinity-rs = self.rustBuilder.workspace;

  dfinity-rs-with-symbols = (
    self.rustBuilder.overrideScope' (
      self_rs: super_rs: {
        makePackageSet = self.rustBuilder.makePackageSet.override {
          mkRustCrate = setFunctionArgs (
            scope: args: super_rs.mkRustCrate scope (
              args // {
                doDoc = false;
                rustcflags = (args.rustcflags or []) ++ [ "-g" ];
              }
            )
          ) (functionArgs super_rs.mkRustCrate);
        };
      }
    )
  ).workspace;

  dfinity-rs-wasm = (
    self.rustBuilder.overrideScope' (
      self_rs: super_rs: {
        makePackageSet = super_rs.makePackageSet.override {
          stdenv = self.stdenv // {
            mkDerivation = args: self.stdenv.mkDerivation (
              args // {
                dontStrip = true;
              }
            );
            cc = self.writeScriptBin "cc" ''
              #!${self.stdenv.shell}
              exec ${self.buildPackages.llvmPackages_11.lld}/bin/lld "$@"
            '' // {
              targetPrefix = "";
            };
            hostPlatform = {
              system = "unknown";
              config = "wasm32-unknown-unknown";
              parsed = {
                cpu.name = "wasm32";
                kernel.name = "unknown";
                abi.name = "unknown";
              };
              isWindows = false;
              isUnix = false;
            };
          };
        };
      }
    )
  ).workspace;
}
