self: super:
let
  inherit (self) lib newScope;
  pkgs = self;
  scope = self:
    let
      inherit (self) callPackage;
    in
      {
        mkLocalRegistry = callPackage ./local-registry.nix {};

        rustLib = callPackage ./lib {};

        makePackageSet = callPackage ./make-package-set/full.nix {};

        makePackageSet' = pkgs.callPackage ./make-package-set/simplified.nix {};

        mkRustCrate = import ./mkcrate.nix;

        mkRustCrateNoBuild = callPackage ./mkcrate-nobuild.nix;

        overrides = callPackage ./overrides.nix {};

        runTests = callPackage ./run-tests.nix {};

        wrapRustc = callPackage ./wrapper.nix {};
      };
in
{
  rustBuilder = lib.makeScope newScope scope;
}
