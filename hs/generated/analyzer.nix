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
, pipes
, pretty-show
, simple-ltl
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
  pname = "analyzer";
  version = "0.0.1";
  src = import ../gitSource.nix pkgs "/hs/analyzer";
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
    pipes
    pretty-show
    simple-ltl
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
    pipes
    pretty-show
    simple-ltl
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
    pipes
    pretty-show
    simple-ltl
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
  description = "Event analyzer";
  license = stdenv.lib.licenses.bsd3;
}
