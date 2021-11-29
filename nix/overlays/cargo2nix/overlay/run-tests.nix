# Run all tests for a crate.
{ stdenvNoCC }:
crate:
env@{ testCommand ? bin: "${bin}"
, ...
}:
let
  testBins = crate { compileMode = "test"; };
in
stdenvNoCC.mkDerivation (
  (removeAttrs env [ "testCommand" ]) // {
    name = "test-${testBins.name}";
    inherit (testBins) src;
    CARGO_MANIFEST_DIR = testBins.src;
    phases = [ "unpackPhase" "buildPhase" ];
    buildPhase = ''
      for f in ${testBins}/bin/*; do
        # HACK: cargo produces the crate's main binary in the bin directory if the crate contains example tests.
        # The `grep` filters out the main binary, which doesn't contain the help string found in test binaries.
        if [[ -x "$f" ]] && grep "By default, all tests are run in parallel" "$f"; then
          ${testCommand "$f"}
        fi
      done
      touch $out
    '';
  }
)
