self: super:

let
  icOverlay = hself: hsuper: with self.haskell.lib; {
    # our packages:
    consensus-model = hself.callPackage ../../hs/generated/consensus-model.nix {};
    analyzer = hself.callPackage ../../hs/generated/analyzer.nix {};
    simple-ltl = hself.callPackage ../../hs/generated/simple-ltl.nix {};

    leb128-cereal = hsuper.callPackage ../../hs/generated/leb128-cereal.nix {};
    candid = hsuper.callPackage ../../hs/generated/candid.nix {};

    # adustments to nixpkgs:

    # Only the test suite of crc is broken
    # https://github.com/MichaelXavier/crc/issues/2
    crc = markUnbroken (dontCheck hsuper.crc);
  };

in
{
  all-cabal-hashes = self.fetchurl {
    url = "https://github.com/commercialhaskell/all-cabal-hashes/archive/b963dde27c24394c4be0031039dae4cb6a363aed.tar.gz";
    sha256 = "1yr9j4ldpi2p2zgdq4mky6y5yh7nilasdmskapbdxp9fxwba2r0x";
  };


  haskell = super.haskell // {
    packageOverrides = self.lib.composeExtensions
      (super.haskell.packageOverrides or (self: super: {})) icOverlay;
  };

  # This is where we set the default haskell packages
  # We do not override haskellPackages, as else tools like shellcheck
  # would be affected
  ourHaskellPackages = self.haskell.packages.ghc884;
}
