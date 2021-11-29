# Creates a derivation for a crate for inputs propagation only.
{ lib, stdenv }:
{ release
, # Compiling in release mode?
  name
, version
, registry
, src
, features ? []
, dependencies ? {}
, devDependencies ? {}
, buildDependencies ? {}
, compileMode ? "build"
, profile
, meta ? {}
, rustcflags ? []
, rustcBuildFlags ? []
, hostPlatformCpu ? null
, hostPlatformFeatures ? []
, extraTestFlags ? (_: [])
}:
with lib; with builtins;
let
  inherit
    (({ right, wrong }: { runtimeDependencies = right; buildtimeDependencies = wrong; })
      (
        partition (drv: drv.stdenv.hostPlatform == stdenv.hostPlatform)
          (
            concatLists [
              (attrValues dependencies)
              (optionals (compileMode == "test") (attrValues devDependencies))
              (attrValues buildDependencies)
            ]
          )
      ))
    runtimeDependencies buildtimeDependencies
    ;
in
stdenv.mkDerivation {
  name = "crate-${name}-${version}";
  propagatedBuildInputs = unique (concatMap (drv: drv.propagatedBuildInputs) runtimeDependencies);
  phases = "installPhase fixupPhase";
  installPhase = "mkdir -p $out";
  preferLocalBuild = true;
  allowSubstitutes = false;
}
