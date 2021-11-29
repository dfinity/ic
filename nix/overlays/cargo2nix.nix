self: super:
let
  defaultOverrides = [ self.rustBuilder.overrides.capLints ];
  inherit (self) lib rustc cargo;

  makeCompilerAttrs = stdenv:
    let
      normalize = builtins.replaceStrings [ "-" ] [ "_" ];
      cfg = normalize stdenv.hostPlatform.config;
      inherit (stdenv.cc) targetPrefix;
    in
      {
        "CARGO_TARGET_${lib.toUpper cfg}_LINKER" = "${stdenv.cc}/bin/${targetPrefix}cc";
        "CC_${cfg}" = "${stdenv.cc}/bin/${targetPrefix}cc";
        "CXX_${cfg}" = "${stdenv.cc}/bin/${targetPrefix}c++";
        "AR_${cfg}" = "${stdenv.cc.bintools.bintools}/bin/${targetPrefix}ar";
      };
in
{
  # The cargo2nix binary, only used in the shell when generating the Cargo.nix
  cargo2nix = self.naersk.buildPackage {
    src = self.lib.gitOnlySource ./cargo2nix;
    root = ./cargo2nix;
    nativeBuildInputs = with self; [ pkg-config openssl curl libgit2 ];
  };

  rustBuilder = super.rustBuilder.overrideScope' (
    self_rs: super_rs: {
      rustLib = super_rs.rustLib // {
        addEnvironment = sel: env:
          let
            overrideName = sel.registry or sel;
          in
            self_rs.rustLib.addDependency sel (
              self_rs.overrides.patches.propagateEnv overrideName (
                self.lib.mapAttrsToList (name: value: { inherit name value; }) env
              )
            );

        addDependencies = sel: deps:
          let
            # addDependencies "some-crate" [ ... ]
            # OR
            # addDependencies { registry = "unknown"; } [ ... ]
            selector =
              if builtins.isString sel then { name = sel; } else sel;
          in
            self_rs.rustLib.makeOverride (
              selector // {
                overrideAttrs = drv: {
                  propagatedBuildInputs = (drv.propagatedBuildInputs or []) ++ deps;
                };
              }
            );

        addDependency = name: dep: self_rs.rustLib.addDependencies name [ dep ];
      };

      mkIcWorkspace =
        { cargoFile
        , crateOverrides ? []
        }:
          let
            pkgFun = args: import cargoFile (
              args // {
                rustLib = args.rustLib // {
                  fetchCrateLocal = self.lib.gitOnlySource;
                };
              }
            );
            wsFun = release: self_rs.makePackageSet {
              packageFun = pkgFun;
              inherit rustc cargo;
              inherit release;
              packageOverrides = defaultOverrides ++ crateOverrides;
              buildRustPackages = super_rs.makePackageSet {
                packageFun = pkgFun;
                inherit rustc cargo;
                release = false;
                packageOverrides = defaultOverrides ++ crateOverrides;
              };
            };
            cratesRelease = wsFun true;
            cratesDebug = wsFun false;
          in
            self.lib.genAttrs (builtins.attrNames cratesRelease.workspace)
              (
                name: rec {
                  release = cratesRelease.workspace.${name} {};
                  debug = cratesDebug.workspace.${name} {};
                  bench = cratesRelease.workspace.${name} { compileMode = "bench"; };
                  test = cratesDebug.workspace.${name} { compileMode = "test"; };
                  test_release = cratesRelease.workspace.${name} { compileMode = "test"; };
                  inherit (release) outPath;
                }
              ) // {
              inherit cratesRelease cratesDebug;
              shell = self.mkCompositeShell (
                {
                  name = "rust-workspace-shell";
                  inputsFrom = map (x: x {}) (builtins.attrValues cratesDebug.noBuild.workspace ++ builtins.attrValues cratesDebug.buildRustPackages.noBuild.workspace);
                  nativeBuildInputs = [
                    (
                      self_rs.rustLib.wrapRustc {
                        rustc = self.rustc;
                        exename = "rustc";
                      }
                    )
                    self.cargo
                  ];
                } // makeCompilerAttrs self.stdenv // makeCompilerAttrs self.pkgsStatic.stdenv
              );
            };
    }
  );
}
