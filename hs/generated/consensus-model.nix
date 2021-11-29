# THIS IS AN AUTOMATICALLY GENERATED FILE. DO NOT EDIT MANUALLY!
# See ./nix/generate.nix for instructions.

{ mkDerivation
, pkgs
, aeson
, arrows
, base
, bytestring
, candid
, constraints
, containers
, cryptohash
, deepseq
, ed25519
, hedgehog
, hpack
, HUnit
, lens
, listsafe
, monad-par
, mtl
, multiset
, pcre-heavy
, pretty-show
, stdenv
, tasty
, tasty-hedgehog
, tasty-hunit
, text
, time
, transformers
, unordered-containers
}:
mkDerivation {
  pname = "consensus-model";
  version = "0.0.1";
  src = import ../gitSource.nix pkgs "/hs/consensus-model";
  isLibrary = true;
  isExecutable = true;
  libraryHaskellDepends = [
    aeson
    arrows
    base
    bytestring
    candid
    constraints
    containers
    cryptohash
    deepseq
    ed25519
    hedgehog
    HUnit
    lens
    listsafe
    monad-par
    mtl
    multiset
    pcre-heavy
    pretty-show
    tasty-hunit
    text
    time
    transformers
    unordered-containers
  ];
  libraryToolDepends = [ hpack ];
  executableHaskellDepends = [
    aeson
    arrows
    base
    bytestring
    candid
    constraints
    containers
    cryptohash
    deepseq
    ed25519
    hedgehog
    HUnit
    lens
    listsafe
    monad-par
    mtl
    multiset
    pcre-heavy
    pretty-show
    tasty-hunit
    text
    time
    transformers
    unordered-containers
  ];
  testHaskellDepends = [
    aeson
    arrows
    base
    bytestring
    candid
    constraints
    containers
    cryptohash
    deepseq
    ed25519
    hedgehog
    HUnit
    lens
    listsafe
    monad-par
    mtl
    multiset
    pcre-heavy
    pretty-show
    tasty
    tasty-hedgehog
    tasty-hunit
    text
    time
    transformers
    unordered-containers
  ];
  prePatch = "hpack";
  homepage = "https://gitlab.com/dfinity-lab/core/ic#readme";
  description = "Various Haskell notes";
  license = stdenv.lib.licenses.bsd3;
}
