{ lib }:
let
  # NOTE(@dingxiangfei2009): override `override`, `overrideDerivation` and `overrideAttrs`
  spliceFunctor =
    { funBuildBuild
    , funBuildHost
    , funBuildTarget
    , funHostHost
    , funHostTarget
    , funTargetTarget
    }:
    arg:
      let
        tryRedex = f: arg: if f == null then null else f arg;
        null2Attrs = v: lib.optionalAttrs (v != null) v;
        defaultFun = lib.findFirst (f: f != null) null [
          funHostTarget
          funBuildHost
          funTargetTarget
          funHostHost
          funBuildTarget
          funBuildBuild
        ];
        defaultValue = defaultFun arg;

        valueBuildBuild = tryRedex funBuildBuild arg;
        valueBuildHost = tryRedex funBuildHost arg;
        valueBuildTarget = tryRedex funBuildTarget arg;
        valueHostHost = tryRedex funHostHost arg;
        valueHostTarget = tryRedex funHostTarget arg;
        valueTargetTarget = tryRedex funTargetTarget arg;
      in
        if lib.isFunction defaultValue then
          spliceFunctor
            {
              funHostTarget = valueHostTarget;
              funBuildHost = valueBuildHost;
              funTargetTarget = valueTargetTarget;
              funHostHost = valueHostHost;
              funBuildTarget = valueBuildTarget;
              funBuildBuild = valueBuildBuild;
            }
        else if lib.isDerivation defaultValue then
          spliceDerivation
            {
              drvHostTarget = null2Attrs valueHostTarget;
              drvBuildHost = null2Attrs valueBuildHost;
              drvTargetTarget = null2Attrs valueTargetTarget;
              drvHostHost = null2Attrs valueHostHost;
              drvBuildTarget = null2Attrs valueBuildTarget;
              drvBuildBuild = null2Attrs valueBuildBuild;
            }
        else if lib.isAttrs defaultValue then
          splicePkgs
            {
              pkgsHostTarget = null2Attrs valueHostTarget;
              pkgsBuildHost = null2Attrs valueBuildHost;
              pkgsTargetTarget = null2Attrs valueTargetTarget;
              pkgsHostHost = null2Attrs valueHostHost;
              pkgsBuildTarget = null2Attrs valueBuildTarget;
              pkgsBuildBuild = null2Attrs valueBuildBuild;
            }
        else
          defaultValue;

  # Taken from <nixpkgs/pkgs/top-level/splice.nix>

  spliceDerivation =
    { drvBuildBuild
    , drvBuildHost
    , drvBuildTarget
    , drvHostHost
    , drvHostTarget
    , drvTargetTarget
    }:
      let
        defaultValue = lib.findFirst (f: f != null && f != {}) null [
          drvHostTarget
          drvBuildHost
          drvTargetTarget
          drvHostHost
          drvBuildTarget
          drvBuildBuild
        ];
        augmentedValue =
          defaultValue
          # TODO(@Ericson2314): Stop using old names after transition period
          // (lib.optionalAttrs (drvBuildHost != null && drvBuildHost != {}) { nativeDrv = drvBuildHost; })
          // (lib.optionalAttrs (drvHostTarget != null && drvHostTarget != {}) { crossDrv = drvHostTarget; })
          // {
            __spliced =
              (lib.optionalAttrs (drvBuildBuild != null) { buildBuild = drvBuildBuild; }) // (lib.optionalAttrs (drvBuildTarget != null) { buildTarget = drvBuildTarget; }) // { hostHost = drvHostHost; } // (lib.optionalAttrs (drvTargetTarget != null) { targetTarget = drvTargetTarget; });
          };
      in
        augmentedValue // splicePkgs {
          pkgsBuildBuild = tryGetOutputs drvBuildBuild;
          pkgsBuildHost = tryGetOutputs drvBuildHost;
          pkgsBuildTarget = tryGetOutputs drvBuildTarget;
          pkgsHostHost = tryGetOutputs drvHostHost;
          pkgsHostTarget = getOutputs drvHostTarget;
          pkgsTargetTarget = tryGetOutputs drvTargetTarget;
        } // lib.optionalAttrs
          (defaultValue ? override && defaultValue ? overrideDerivation)
          {
            override = spliceFunctor {
              funBuildBuild = drvBuildBuild.override or null;
              funBuildHost = drvBuildHost.override or null;
              funBuildTarget = drvBuildTarget.override or null;
              funHostHost = drvHostHost.override or null;
              funHostTarget = drvHostTarget.override or null;
              funTargetTarget = drvTargetTarget.override or null;
            };
            overrideDerivation = spliceFunctor {
              funBuildBuild = drvBuildBuild.overrideDerivation or null;
              funBuildHost = drvBuildHost.overrideDerivation or null;
              funBuildTarget = drvBuildTarget.overrideDerivation or null;
              funHostHost = drvHostHost.overrideDerivation or null;
              funHostTarget = drvHostTarget.overrideDerivation or null;
              funTargetTarget = drvTargetTarget.overrideDerivation or null;
            };
          };

  # Get the set of outputs of a derivation. If one derivation fails to
  # evaluate we don't want to diverge the entire splice, so we fall back
  # on {}
  tryGetOutputs = value0:
    let
      inherit (builtins.tryEval value0) success value;
    in
      getOutputs (lib.optionalAttrs success value);

  getOutputs = value:
    lib.genAttrs
      (value.outputs or (lib.optional (value ? out) "out"))
      (output: value.${output});

  splicePkgs =
    { pkgsBuildBuild
    , pkgsBuildHost
    , pkgsBuildTarget
    , pkgsHostHost
    , pkgsHostTarget
    , pkgsTargetTarget
    }:
      let
        mash =
          # Other pkgs sets
          pkgsBuildBuild // pkgsBuildTarget // pkgsHostHost // pkgsTargetTarget // # The same pkgs sets one probably intends
          pkgsBuildHost // pkgsHostTarget;
        merge = name: {
          inherit name;
          value =
            let
              defaultValue = mash.${name};
            in
              if lib.isFunction defaultValue then
                spliceFunctor
                  {
                    funBuildBuild = pkgsBuildBuild.${name} or null;
                    funBuildHost = pkgsBuildHost.${name} or null;
                    funBuildTarget = pkgsBuildTarget.${name} or null;
                    funHostHost = pkgsHostHost.${name} or null;
                    funHostTarget = pkgsHostTarget.${name} or null;
                    funTargetTarget = pkgsTargetTarget.${name} or null;
                  }
              else if lib.isDerivation defaultValue then
                # The derivation along with its outputs, which we recur
                # on to splice them together.
                spliceDerivation
                  {
                    drvBuildBuild = pkgsBuildBuild.${name} or null;
                    drvBuildHost = pkgsBuildHost.${name} or null;
                    drvBuildTarget = pkgsBuildTarget.${name} or null;
                    drvHostHost = pkgsHostHost.${name} or null;
                    drvHostTarget = pkgsHostTarget.${name} or null;
                    drvTargetTarget = pkgsTargetTarget.${name} or null;
                  }
              else if lib.isAttrs defaultValue then
                # Just recur on plain attrsets
                splicePkgs
                  {
                    pkgsBuildBuild = pkgsBuildBuild.${name} or {};
                    pkgsBuildHost = pkgsBuildHost.${name} or {};
                    pkgsBuildTarget = pkgsBuildTarget.${name} or {};
                    pkgsHostHost = pkgsHostHost.${name} or {};
                    pkgsHostTarget = pkgsHostTarget.${name} or {};
                    pkgsTargetTarget = pkgsTargetTarget.${name} or {};
                  }
              else
                defaultValue;
        };
      in
        lib.listToAttrs (map merge (lib.attrNames mash));

  splicePackages =
    actuallySplice:
    { pkgsBuildBuild
    , pkgsBuildHost
    , pkgsBuildTarget
    , pkgsHostHost
    , pkgsHostTarget
    , pkgsTargetTarget
    } @ args:
      if actuallySplice then
        splicePkgs args
      else
        pkgsHostTarget;
in
{ inherit splicePackages; }
