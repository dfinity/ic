{ pkgs
, lib
, rustBuilder
, rustLib
, stdenv
, mkRustCrate
, mkRustCrateNoBuild
,
}:
{ packageFun
, cargo
, rustc
, buildRustPackages ? null
, fetchCrateLocal ? path: (lib.sourceByRegex path localPatterns).outPath
, localPatterns ? [ ''^(src|tests)(/.*)?'' ''[^/]*\.(rs|toml)$'' ]
, packageOverrides ? rustBuilder.overrides.all
, fetchCrateAlternativeRegistry ? _: throw "fetchCrateAlternativeRegistry is required, but not specified in makePackageSet"
, release ? null
, rootFeatures ? null
, hostPlatformCpu ? null
, hostPlatformFeatures ? []
,
}:
lib.fix' (
  self:
    let
      rustPackages = self;
      buildRustPackages' = if buildRustPackages == null then self else buildRustPackages;
      mkScope = scope:
        let
          prevStage = pkgs.__splicedPackages;
          scopeSpliced = rustLib.splicePackages (buildRustPackages != null)
            {
              pkgsBuildBuild = scope.buildRustPackages.buildRustPackages;
              pkgsBuildHost = scope.buildRustPackages;
              pkgsBuildTarget = {};
              pkgsHostHost = {};
              pkgsHostTarget = scope;
              pkgsTargetTarget = {};
            } // {
            inherit (scope) pkgs buildRustPackages cargo rustc config __splicedPackages;
          };
        in
          prevStage // prevStage.xorg // prevStage.gnome2 // { inherit stdenv; } // scopeSpliced;
      defaultScope = mkScope self;
      callPackage = lib.callPackageWith defaultScope;

      mkRustCrate' = lib.makeOverridable (callPackage mkRustCrate { inherit rustLib; });
      combinedOverride = builtins.foldl' rustLib.combineOverrides rustLib.nullOverride packageOverrides;
      packageFunWith = { mkRustCrate, buildRustPackages }: lib.fix (
        rustPackages: packageFun {
          inherit rustPackages buildRustPackages lib;
          inherit (stdenv) hostPlatform;
          mkRustCrate = rustLib.runOverride combinedOverride mkRustCrate;
          rustLib = rustLib // {
            inherit fetchCrateAlternativeRegistry fetchCrateLocal;
          };
          ${ if release == null then null else "release" } = release;
          ${ if rootFeatures == null then null else "rootFeatures" } = rootFeatures;
          ${ if hostPlatformCpu == null then null else "hostPlatformCpu" } = hostPlatformCpu;
          ${ if hostPlatformFeatures == null then null else "hostPlatformFeatures" } = hostPlatformFeatures;
        }
      );

    in
      packageFunWith { mkRustCrate = mkRustCrate'; buildRustPackages = buildRustPackages'; } // {
        inherit rustPackages callPackage cargo rustc pkgs;
        noBuild = packageFunWith {
          mkRustCrate = lib.makeOverridable mkRustCrateNoBuild {};
          buildRustPackages = buildRustPackages'.noBuild;
        };
        mkRustCrate = mkRustCrate';
        buildRustPackages = buildRustPackages';
        __splicedPackages = defaultScope;
      }
)
