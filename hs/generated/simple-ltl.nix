# THIS IS AN AUTOMATICALLY GENERATED FILE. DO NOT EDIT MANUALLY!
# See ./nix/generate.nix for instructions.

{ mkDerivation
, pkgs
, base
, criterion
, deepseq
, stdenv
, tasty
, tasty-hunit
}:
mkDerivation {
  pname = "simple-ltl";
  version = "3.0.0";
  src = import ../gitSource.nix pkgs "/hs/simple-ltl";
  libraryHaskellDepends = [ base deepseq ];
  testHaskellDepends = [ base tasty tasty-hunit ];
  benchmarkHaskellDepends = [ base criterion ];
  homepage = "https://www.github.com/jwiegley/simple-ltl";
  description = "A simple LTL checker";
  license = stdenv.lib.licenses.bsd3;
}
