[
  (
    self: super:
      {

        # The 'pre-commit' tool that we use for a lot of checks (formatting, etc)
        # https://pre-commit.com
        pre-commit = self.python3.withPackages (pythonPackages: [ pythonPackages.pre-commit ]);

        # used by the rosetta-api tests
        # we don't build from source because the build is somewhat involved
        # and buildGoModule fails on missing includes that aren't easy to
        # inject.
        rosetta-cli = self.runCommand "rosetta-cli" {}
          ''
            tar -xvzf ${self.sources."rosetta-cli-${self.stdenv.system}"}
            exe=$(find . -name 'rosetta*')

            echo "exe is $exe"

            ${ # on Linux we need to set the correct interpreter
          if self.stdenv.isLinux then ''
            interp=$("${self.glibc.bin}/bin/ldd" "$exe" | grep 'ld-linux-x86-64' | awk '/ => / { print $3 }')

            echo "setting interpreter to $interp"

            "${self.patchelf}/bin/patchelf" --set-interpreter "$interp" "$exe"
            "${self.glibc.bin}/bin/ldd" "$exe"
          '' else ""
          }

            mkdir -p $out/bin

            cp "$exe" $out/bin/rosetta-cli

            # just make sure everything is linked properly
            $out/bin/rosetta-cli --help
          '';

        lib = super.lib // {
          runBenchmarks = self.callPackage ../benchmarks {};
        };
        isMaster = super.isMaster or false;

        sdk = import (self.sources.sdk + /ci/ci.nix) {
          releaseVersion = self.sources.sdk.tag or "latest";
        };

        dfx = self.callPackage ./dfx.nix {};

        idl2json = import self.sources.idl2json {
          inherit (self) pkgs;
        };

        cargo-flamegraph =
          self.naersk.buildPackage self.sources.cargo-flamegraph;

        # Subcommand to show result of macro expansion
        cargo-expand =
          self.naersk.buildPackage
            {
              src = self.sources.cargo-expand;
              buildInputs = self.lib.optional self.stdenv.isDarwin self.xcbuild;
            };

        ic-cdk-optimizer = self.callPackage ./ic-cdk-optimizer {};

        # The rust code-coverage tool. As per the doc, only runs on Linux
        # (doesn't even build on Darwin).
        cargo-tarpaulin = self.lib.linuxOnly (
          self.naersk.buildPackage {
            src = self.sources.tarpaulin;
            doCheck = false;
            buildInputs = [ self.openssl self.pkg-config self.libiconv ];
          }
        );
        cargo-graph = self.naersk.buildPackage self.sources.cargo-graph;

        rocksdb = super.callPackage ./rocksdb {};

        # LMDB 0.9.24 does not provide MDB_SYSV_SEM option, so we have to use a newer one.
        lmdb = super.callPackage ./lmdb {};
        lmdb_static = self.pkgsStatic.lmdb;

        rocksdb_static = self.pkgsStatic.rocksdb.override {
          enableShared = false;
          bzip2 = self.bzip2_static;
          lz4 = self.lz4_static;
          snappy = self.snappy_static;
          zlib = self.zlib_static;
          zstd = self.zstd_static;
        };

        rocksdb_static_jemalloc = self.rocksdb_static.override {
          enableJemalloc = true;
          jemalloc = self.jemalloc_static;
        };

        snappy_static = self.pkgsStatic.snappy.override { static = true; };

        lz4_static = self.pkgsStatic.lz4.override {
          enableStatic = true;
          enableShared = false;
        };

        zlib_static = self.pkgsStatic.zlib.override {
          shared = false;
          splitStaticOutput = false;
        };

        bzip2_static = self.pkgsStatic.bzip2.override { linkStatic = true; };

        zstd_static = self.pkgsStatic.zstd.override { static = true; };

        jemalloc_static = self.pkgsStatic.jemalloc;

        ic-ref = self.ic-ref-0_16;

        ic-ref-0_16 = (import self.sources.ic-ref-0_16 { inherit (self) system; }).ic-ref;
        ic-ref-0_17 = (import self.sources.ic-ref-0_17 { inherit (self) system; }).ic-ref;
        ic-ref-0_18 = (import self.sources.ic-ref-0_18 { inherit (self) system; }).ic-ref;

        buf = super.callPackage ./buf {};

        clipboard = super.callPackage ./clipboard {};

        ansible_2_10 = super.ansible_2_10.overrideAttrs (
          _oldAttrs: rec {
            src = self.sources.ansible;
            inherit (src) version;
            name = "ansible-${version}";
          }
        );

        # We add some extra configuration to Ansible. Because the
        # configuration is dynamic (depends on store entries) we can't set it
        # in ansible.cfg. Instead we set it through environment variables.
        # ANSIBLE_STRATEGY*: set up mitogen
        ansible = self.runCommandNoCC "ansible-wrapped" rec {
          ansible = self.ansible_2_10;
          inherit (self.sources) mitogen;
          ansible_collections = self.runCommandNoCC "ansible-collections" {
            nativeBuildInputs = [ ansible self.cacert ];
            collections = [
              "ansible.posix:1.2.0" # provides the required "debug" callback plugin.
              "community.libvirt:1.0.1" # needed to deploy IC-OS guest VMs.
              "community.general:2.5.1" # needed to deploy IC-OS guest VMs.
            ];
            outputHashMode = "recursive";
            outputHashAlgo = "sha256";
            outputHash = "06na37dinir4yf4vh5g2ib9fq6bx4j161vnb11pfbmlw42gy6mk4";
          } ''
            export HOME="$NIX_BUILD_TOP"
            ansible-galaxy collection install -p $out $collections
          '';
        }
          ''
            mkdir -p $out/bin
            for exe in $ansible/bin/*; do
              exe=$(basename $exe)
              echo \
                ANSIBLE_STRATEGY_PLUGINS=$mitogen/ansible_mitogen/plugins/strategy \
                ANSIBLE_STRATEGY=mitogen_linear \
                ANSIBLE_COLLECTIONS_PATHS=$ansible_collections \
                "$ansible/bin/$exe" '"$@"' >> "$out/bin/$exe"
              chmod +x "$out/bin/$exe"
            done
          '';

        # ansible-lint has ansible as a propagatedBuildInput. This means that
        # bringing ansible-lint into scope in a shell will also bring that
        # version of ansible into scope. That version of ansible is different
        # from the override above which means that there's a risk that our own
        # version of ansible gets overridden by the one brought into scope by
        # ansible-lint. To fix this we only copy the bin and lib directories
        # of ansible-lint and ignore the nix-support directory which would
        # bring the wrong ansible into scope.
        ansible-lint = self.runCommandNoCC super.ansible-lint.name {
          ansible_lint = super.ansible-lint;
        } ''
          mkdir $out
          cp -r $ansible_lint/{bin,lib} $out/
        '';

        # An attribute set mapping every supported system to a nixpkgs evaluated for
        # that system. Special care is taken not to reevaluate nixpkgs for the current
        # system because we already did that in self.
        pkgsForSystem = super.lib.genAttrs [ "x86_64-linux" "x86_64-darwin" ] (
          supportedSystem:
            if supportedSystem == super.system
            then self
            else import ../. { system = supportedSystem; }
        );

        # Use a recent version of python-gitlab
        python3Packages = super.python3Packages // {
          python-gitlab = super.python3Packages.python-gitlab.overrideAttrs (
            oldAttrs: rec {
              name = "${pname}-${version}";
              pname = "python-gitlab";
              version = "2.6.0";
              src = self.python3Packages.fetchPypi {
                inherit pname version;
                sha256 = "18fa5n7lwamy245g81a2szb0kz2h576v45ssf9dmiar48n3wcqm8";
              };
              propagatedBuildInputs = oldAttrs.propagatedBuildInputs ++ [
                self.python3Packages.requests-toolbelt
              ];
            }
          );
        };
      }
  )
  (import ./haskell.nix)
  (import ./motoko.nix)
]
