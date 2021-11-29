# THIS IS AN AUTOMATICALLY GENERATED FILE. DO NOT EDIT MANUALLY!
# See ./nix/generate.nix for instructions.

{ mkDerivation
, pkgs
, base
, bytestring
, cereal
, stdenv
, tasty
, tasty-hunit
, tasty-quickcheck
}:
mkDerivation {
  pname = "leb128-cereal";
  version = "1.2";
  src = pkgs.sources.leb128-cereal;
  libraryHaskellDepends = [ base bytestring cereal ];
  testHaskellDepends = [
    base
    bytestring
    tasty
    tasty-hunit
    tasty-quickcheck
  ];
  description = "LEB128 and SLEB128 encoding";
  license = stdenv.lib.licenses.mit;
}
