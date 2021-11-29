{ stdenv, sources, runCommandNoCC }:

let
  src = sources."dfx-${stdenv.system}";
in

runCommandNoCC "dfx-${src.version}" {
  inherit src;
} ''
  tar xf $src
  mkdir -p $out/bin
  mv dfx $out/bin/dfx
''
