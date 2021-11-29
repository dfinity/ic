{ wasm-c-api-debug ? false, stdenv, wasm-c-api-src
, v8_7_x, cmake, perl, static ? false }:

with { arch = "x64"; };

stdenv.mkDerivation rec {
  name = "wasm-c-api";
  src = wasm-c-api-src;

  postConfigure = stdenv.lib.optionalString (!static) ''
    cat > script.pl <<'EOF'
while (<ARGV>) {
  if (/^V8_LIBS/) {
    print "V8_LIBS = libbase libplatform\n";
  }
  elsif (/\''${V8_LIBS/) {
    print "\t\t-L${v8_7_x}/lib \''${V8_LIBS:%=-lv8_%} -lv8 \\\n";
  }
  else {
    print $_;
  }
'' + stdenv.lib.optionalString (!static && stdenv.isDarwin) ''
  if (/-ldl -pthread/) {
    print "\tinstall_name_tool -change '\@rpath/libv8.dylib' ${v8_7_x}/lib/libv8.dylib \$@\n";
    print "\tinstall_name_tool -change '\@rpath/libv8_libbase.dylib' ${v8_7_x}/lib/libv8_libbase.dylib \$@\n";
    print "\tinstall_name_tool -change '\@rpath/libv8_libplatform.dylib' ${v8_7_x}/lib/libv8_libplatform.dylib \$@\n";
  }
'' + stdenv.lib.optionalString (!static) ''
}
EOF
    ${perl}/bin/perl -i -n script.pl Makefile
  '';

  buildPhase = ''
    mkdir -p v8/v8/out.gn/${arch}.release
    ln -sv ${v8_7_x}/include v8/v8/include
    ln -sv ${v8_7_x}/lib     v8/v8/out.gn/${arch}.release/obj
    substituteInPlace Makefile                          \
        --replace "-fsanitize=address"               "" \
        --replace "-fsanitize-memory-track-origins"  "" \
        --replace "-fsanitize-memory-use-after-dtor" "" \
        --replace "-ggdb -O" "-O2"
    make V8_LIBDIR=${v8_7_x}/lib -j "$NIX_BUILD_CORES" \
        ${if wasm-c-api-debug
          then ''WASM_FLAGS="-DDEBUG"''
          else ''WASM_FLAGS=''}
  ''
  + (if static
     then ''
       ar rvs libv8_wasm.a out/{wasm-bin,wasm-c}.o
     ''
     else
       let libcpp = "${if stdenv.isDarwin then "" else "std"}c++"; in ''
       clang ${if stdenv.isDarwin then "-dynamiclib" else "-shared"} \
         out/{wasm-bin,wasm-c}.o \
         -std=c++14 -stdlib=lib${libcpp} -fno-exceptions -fno-rtti \
         -o libv8_wasm.${if stdenv.isDarwin then "dylib" else "so"} \
         -l${libcpp} -L${v8_7_x}/lib -lv8 -lv8_libbase -lv8_libplatform
     '')
  + stdenv.lib.optionalString stdenv.isDarwin ''
    install_name_tool -id $out/lib/libv8_wasm.dylib libv8_wasm.dylib
  '';

  # We split-up the outputs primarily because the `example` directory
  # contains a file referencing GCC which will end up in a closure of
  # any package depending on wasm-c-api.
  #
  # Ideally we use `lib` instead of `out` but that fails with the error
  # as mentioned in: https://github.com/NixOS/nixpkgs/issues/16182
  outputs = [ "out" "dev" "devdoc" ];

  installPhase = ''
    mkdir -pv $out/{lib,wasm} $dev/include $devdoc/example
    cp -v out/example/* "$devdoc/example/"
    cp -v out/*.o       "$out/wasm/"
    cp -v libv8_wasm.*  "$out/lib/"
    cp -v include/*     "$dev/include/"
  '';
}
