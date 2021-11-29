{ runCommandNoCC, stdenv }:
{ rustc, exename }:

runCommandNoCC "${exename}-wrapper"
  {
    inherit (stdenv) shell;
    inherit rustc exename;
    utils = ../utils.sh;
  } ''
  mkdir -p $out/bin
  substituteAll ${../wrapper.sh} $out/bin/$exename
  chmod +x $out/bin/$exename
''
