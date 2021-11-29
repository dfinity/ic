# An overrider has the ability to modify the arguments passed to a function. It takes the original set of arguments
# and returns a new set of arguments, which will then be merged with the original set to become the new arguments
# to the original function.
# type Overrider = Attrs -> Attrs
#
# An override has the ability to modify the arguments passed to a function, and the attribute
# set of the derivation returned by that function. It takes the original set of arguments and
# optionally returns 2 overriders: `overrideArgs`, which overrides the argument set, and `overrideAttr`,
# which overrides the derivation attributes.
# See https://nixos.org/nixpkgs/manual/#sec-pkg-override for more information on `overrideArgs`, and
# https://nixos.org/nixpkgs/manual/#sec-pkg-overrideAttrs for `overrideAttrs`.
# type Override = Attrs -> { overrideArgs: Maybe Overrider, overrideAttrs: Maybe Overrider }
{}:
let
  combineOverriders = a: b:
    if a == null then b
    else if b == null then a
    else oldAttrs:
      let attrs = oldAttrs // a oldAttrs; in attrs // b attrs;

  nullOverriders = { overrideArgs = null; overrideAttrs = null; };
in
{
  # Constructs an override for `mkRustCrate`.
  # - `registry`, `name`, `version` specify which crates this override applies to.
  # - `overrideArgs` overrides the argument set passed to `mkRustCrate`.
  # - `overrideAttrs` overrides the attribute set of the derivation returned by `mkRustCrate`.
  makeOverride = args@{ registry ? null, name ? null, version ? null, overrideArgs ? null, overrideAttrs ? null }:
    assert overrideArgs != null || overrideAttrs != null;
    let
      matcher = builtins.intersectAttrs { registry = {}; name = {}; version = {}; } args;
      overriders = { inherit overrideArgs overrideAttrs; };
    in
      args:
        if builtins.intersectAttrs matcher args == matcher
        then overriders
        else nullOverriders;

  combineOverrides = left: right: args:
    let
      leftOverriders = left args;
      rightOverriders = right args;
    in
      {
        overrideArgs = combineOverriders leftOverriders.overrideArgs rightOverriders.overrideArgs;
        overrideAttrs = combineOverriders leftOverriders.overrideAttrs rightOverriders.overrideAttrs;
      };

  # Applies an override to a function.
  runOverride = override: f: args:
    let
      overriders = override args;
      drv = f (if overriders.overrideArgs == null then args else (args // overriders.overrideArgs args));
    in
      if overriders.overrideAttrs == null then drv else drv.overrideAttrs overriders.overrideAttrs;

  nullOverride = _: nullOverriders;
}
