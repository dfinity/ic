{ pkgs
, buildPackages
, stdenv
, rustBuilder
,
}:
args@{ rustChannel
, packageFun
, packageOverrides ? pkgs: pkgs.rustBuilder.overrides.all
, ...
}:
let
  rustChannel = buildPackages.rustChannelOf {
    channel = args.rustChannel;
  };
  inherit (rustChannel) cargo;
  rustc = rustChannel.rust.override {
    targets = [
      (rustBuilder.rustLib.realHostTriple stdenv.targetPlatform)
    ];
  };
  extraArgs = builtins.removeAttrs args [ "rustChannel" "packageFun" "packageOverrides" ];
in
rustBuilder.makePackageSet (
  extraArgs // {
    inherit cargo rustc packageFun;
    packageOverrides = packageOverrides pkgs;
    buildRustPackages = buildPackages.rustBuilder.makePackageSet (
      extraArgs // {
        inherit cargo rustc packageFun;
        packageOverrides = packageOverrides buildPackages;
      }
    );
  }
)
