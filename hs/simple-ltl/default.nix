{ ghcCompiler ? "ghc8104"

, rev ? "c74fa74867a3cce6ab8371dfc03289d9cc72a66e"
, sha256 ? "13bnmpdmh1h6pb7pfzw5w3hm6nzkg9s1kcrwgw1gmdlhivrmnx75"
, pkgs ? import
    (
      builtins.fetchTarball {
        url = "https://github.com/NixOS/nixpkgs/archive/${rev}.tar.gz";
        inherit sha256;
      }
    ) {
    config.allowUnfree = true;
    config.allowBroken = false;
  }

, returnShellEnv ? pkgs.lib.inNixShell
, mkDerivation ? null
}:

let
  haskellPackages = pkgs.haskell.packages.${ghcCompiler};

in
haskellPackages.developPackage rec {
  # name = "haskell-${ghcCompiler}-simple-ltl";
  root = ./.;

  source-overrides = {};
  overrides = self: super: with pkgs.haskell.lib; {};

  modifier = drv:
    pkgs.haskell.lib.overrideCabal drv (
      attrs: {
        buildTools = (attrs.buildTools or []) ++ [
          haskellPackages.cabal-install
          haskellPackages.hpack
          haskellPackages.hoogle
          haskellPackages.hasktags
          haskellPackages.ghcid
          haskellPackages.ormolu
        ];

        benchmarkDepends = (attrs.benchmarkDepends or [])
        ++ [ pkgs.haskellPackages.criterion ];

        doBenchmark = true;

        passthru = {
          nixpkgs = pkgs;
          inherit haskellPackages;
        };
      }
    );

  inherit returnShellEnv;
}
