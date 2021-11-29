{ system ? builtins.currentSystem
, config ? {}
, overlays ? []
, crossSystem ? null
, pkgs ? import ../nix { inherit system config overlays crossSystem; }
, rs ? import ../rs { inherit pkgs; }
}:

let
  useful-shell-pkgs =
    with pkgs.ourHaskellPackages; [
      cabal-install
      ormolu
      ghcid
      hoogle
      hasktags
    ];

  make-hs-shell = d:
    (d.envFunc { withHoogle = true; }).overrideAttrs (
      old:
        { buildInputs = old.buildInputs ++ useful-shell-pkgs; }
    );

  mkRelease = pkgs.callPackage ../rs/mk-release.nix {};

  inherit (pkgs.haskell.lib) justStaticExecutables;
in
rec {
  simple-ltl = pkgs.ourHaskellPackages.simple-ltl;
  simple-ltl-shell = make-hs-shell pkgs.ourHaskellPackages.simple-ltl;

  consensus-model = justStaticExecutables pkgs.ourHaskellPackages.consensus-model;
  consensus-model-shell = make-hs-shell pkgs.ourHaskellPackages.consensus-model;

  analyzer = justStaticExecutables pkgs.ourHaskellPackages.analyzer;
  analyzer-shell = make-hs-shell pkgs.ourHaskellPackages.analyzer;

  check-generated = pkgs.runCommandNoCC "check-generated" {
    nativeBuildInputs = [ pkgs.diffutils ];
    expected = pkgs.callPackage ./generate.nix {};
    dir = ./generated;
  } ''
    diff -r -U 3 $expected $dir
    touch $out
  '';
}
