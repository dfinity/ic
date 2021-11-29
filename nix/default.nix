# Returns the nixpkgs set overridden and extended with IC specific
# packages.
{ system ? builtins.currentSystem
, crossSystem ? null
, config ? {}
, overlays ? []
, isMaster ? true
, labels ? {}
}:
assert (
  if builtins.getEnv "COMMON" != "" then
    builtins.trace "WARNING\n  Please set NIV_OVERRIDE_common instead of COMMON\n  Read more at: https://github.com/nmattia/niv/#can-i-use-local-packages" true
  else true
);

let
  sources = import sourcesnix { sourcesFile = ./sources.json; inherit pkgs; };

  sourcesnix = builtins.fetchurl {
    url = https://raw.githubusercontent.com/nmattia/niv/d13bf5ff11850f49f4282d59b25661c45a851936/nix/sources.nix;
    sha256 = "0a2rhxli7ss4wixppfwks0hy3zpazwm9l3y2v9krrnyiska3qfrw";
  };

  pkgs = import (sources.common + "/pkgs") {
    inherit system crossSystem config isMaster labels;
    repoRoot = ../.;
    extraSources = sources;
    overlays = import ./overlays ++ overlays;
  };
in
pkgs
