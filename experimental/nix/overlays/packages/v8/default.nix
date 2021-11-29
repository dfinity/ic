{ stdenv, lib, fetchgit, fetchFromGitHub, at-spi2-atk, at-spi2-core, dbus, gn,
  ninja, python, glib, pkgconfig, which, xcbuild, darwin, llvmPackages_7,
  symlinkJoin, static ? false, wasm-c-api-src
}:

let
  # for use with `clang_base_path` in `v8` derivation
  llvm-packages-v8 = symlinkJoin {
    name = "llvm-packages-v8";
    paths = with llvmPackages_7; [ stdenv.cc llvm lld clang ];
  };

  git_url = "https://chromium.googlesource.com";

  arch = if stdenv.isAarch32
         then (if stdenv.is64bit then "arm64" else "arm")
         else (if stdenv.is64bit then "x64"   else "ia32");

  # This data is from the DEPS file in the root of a V8 checkout
  deps = {
    "base/trace_event/common" = fetchgit {
      url    = "${git_url}/chromium/src/base/trace_event/common.git";
      rev    = "cfe8887fa6ac3170e23a68949930e28d4705a16f";
      sha256 = "1vplka76nhml9a5ri43r5nvsdww8hv4p3prhf1vfvsrhxhmy3hrh";
    };
    "build" = fetchgit {
      url    = "${git_url}/chromium/src/build.git";
      rev    = "4cebfa34c79bcfbce6a3f55d1b4f7628bb70ea8a";
      sha256 = "0xmcj70ldd6s60pszx8w5xs9a24q0p5wcicdyr80h3r8myvbh3g1";
    };
    "buildtools" = fetchgit {
      url    = "${git_url}/chromium/src/buildtools.git";
      rev    = "0218c0f9ac9fdba00e5c27b5aca94d3a64c74f34";
      sha256 = "0mcn1nnm6xxq0mlbqjr9vj84snvqpnfd8c6ms28jfsc000awj93x";
    };
    "test/benchmarks/data" = fetchgit {
      url    = "${git_url}/v8/deps/third_party/benchmarks.git";
      rev    = "05d7188267b4560491ff9155c5ee13e207ecd65f";
      sha256 = "0ad2ay14bn67d61ks4dmzadfnhkj9bw28r4yjdjjyzck7qbnzchl";
    };
    "test/mozilla/data" = fetchgit {
      url    = "${git_url}/v8/deps/third_party/mozilla-tests.git";
      rev    = "f6c578a10ea707b1a8ab0b88943fe5115ce2b9be";
      sha256 = "0rfdan76yfawqxbwwb35aa57b723j3z9fx5a2w16nls02yk2kqyn";
    };
    "test/test262/data" = fetchgit {
      url    = "${git_url}/external/github.com/tc39/test262.git";
      rev    = "a9abd418ccc7999b00b8c7df60b25620a7d3c541";
      sha256 = "1bdmdpjgbvzrw9j2cyg4kays9nd2y2k0vr1nkb4q1jvdp3is6y6f";
    };
    "test/test262/harness" = fetchgit {
      url    = "${git_url}/external/github.com/test262-utils/test262-harness-py.git";
      rev    = "4555345a943d0c99a9461182705543fb171dda4b";
      sha256 = "03hxwgx5jimwlwsi77n5bf6661w6pwxb8ykjjq1dyzha2l7i6a2x";
    };
    "test/wasm-js/data" = fetchgit {
      url    = "${git_url}/external/github.com/WebAssembly/spec.git";
      rev    = "bc7d3006bbda0de5031c2a1b9266a62fa7895019";
      sha256 = "0vqi62yl79pgmqzfad8b3fxkxslva8ygv4lh0bch8hhi96l1vv3y";
    };
    "third_party/depot_tools" = fetchgit {
      url    = "${git_url}/chromium/tools/depot_tools.git";
      rev    = "26af0d34d281440ad0dc6d2e43fe60f32ef62da0";
      sha256 = "1r4d4qmphyvc2gh9xsicb196p3pcdva42kvmr99kas65xsdg6887";
    };
    "third_party/googletest/src" = fetchgit {
      url    = "${git_url}/external/github.com/google/googletest.git";
      rev    = "f71fb4f9a912ec945401cc49a287a759b6131026";
      sha256 = "1ac66frha0hw50zdqdrs7pp5jips489rjw5jwynfdnqwsdw05197";
    };
    "third_party/icu" = fetchgit {
      url    = "${git_url}/chromium/deps/icu.git";
      rev    = "64e5d7d43a1ff205e3787ab6150bbc1a1837332b";
      sha256 = "06j1q9yfp3mxlpw0y82r2h4bwmdkdzdwm4hv5nfg9ryb0wc473xw";
    };
    "third_party/instrumented_libraries" = fetchgit {
      url    = "${git_url}/chromium/src/third_party/instrumented_libraries.git";
      rev    = "a959e4f0cb643003f2d75d179cede449979e3e77";
      sha256 = "1irjsddn6agih9pm6nhb0s77xwr6k33fbc8yiyb55b1gal2j0ik5";
    };
    "third_party/jinja2" = fetchgit {
      url    = "${git_url}/chromium/src/third_party/jinja2.git";
      rev    = "b41863e42637544c2941b574c7877d3e1f663e25";
      sha256 = "1qgilclkav67m6cl2xq2kmzkswrkrb2axc2z8mw58fnch4j1jf1r";
    };
    "third_party/markupsafe" = fetchgit {
      url    = "${git_url}/chromium/src/third_party/markupsafe.git";
      rev    = "8f45f5cfa0009d2a70589bcda0349b8cb2b72783";
      sha256 = "168ppjmicfdh4i1l0l25s86mdbrz9fgxmiq1rx33x79mph41scfz";
    };
    "third_party/perfetto" = fetchgit {
      url    = "https://android.googlesource.com/platform/external/perfetto.git";
      rev    = "10c98fe0cfae669f71610d97e9da94260a6da173";
      sha256 = "09x7bfj1qvd060yy7h2gcfy1vjz1lzbbsmnqa0083sbxjbwhlqxy";
    };
    "third_party/protobuf" = fetchgit {
      url    = "${git_url}/external/github.com/google/protobuf";
      rev    = "b68a347f56137b4b1a746e8c7438495a6ac1bd91";
      sha256 = "07ny4ixa2zkhdgxxiici0j31nwx1dl7in4ymj7jc3ql7j894i7h8";
    };
    "tools/clang" = fetchgit {
      url    = "${git_url}/chromium/src/tools/clang.git";
      rev    = "fe8ba88894e4b3927d3cd9e24274a0f1a688cf71";
      sha256 = "0j1hs33z38xq5lg62m7askdsmi9rw82a99b8c1gglbywnwcihrky";
    };
  };
in

stdenv.mkDerivation rec {
  name = "v8-${version}";
  version = "7.6.303.28";

  src = builtins.fetchGit {
    url = "https://chromium.googlesource.com/v8/v8.git";
    ref = version;
    rev = "b42aafe35d48f10e5fdfa6786dbe3fecaec1ac70";
  };

  patches = "${wasm-c-api-src}/patch/*.patch";

  doCheck = false;

  nativeBuildInputs = [ at-spi2-atk at-spi2-core dbus gn ninja pkgconfig ];
  buildInputs = [ python glib llvm-packages-v8 ]
    ++ stdenv.lib.optionals stdenv.isDarwin [ which xcbuild ];

  enableParallelBuilding = true;

  postUnpack = ''
    ${lib.concatStringsSep "\n" (
      lib.mapAttrsToList (n: v: ''
        mkdir -p $sourceRoot/${n}
        cp -r ${v}/* $sourceRoot/${n}
      '') deps)}
  '';

  prePatch = ''
    cp ${wasm-c-api-src}/src/wasm-v8-lowlevel.cc src/wasm-v8-lowlevel.cc
    cp ${wasm-c-api-src}/src/wasm-v8-lowlevel.hh include/wasm-v8-lowlevel.hh
    # use our gn, not the bundled one
    sed -i -e 's#gn_path = .*#gn_path = "${gn}/bin/gn"#' tools/mb/mb.py

    # disable tests
    if [ "$doCheck" = "" ]; then sed -i -e '/"test:gn_all",/d' BUILD.gn; fi

    # disable sysroot usage
    chmod u+w build/config build/config/sysroot.gni
    sed -i build/config/sysroot.gni \
        -e '/use_sysroot =/ { s#\(use_sysroot =\).*#\1 false#; :a  n; /current_cpu/ { s/^/#/; ba };  }'

    # patch shebangs (/usr/bin/env)
    patchShebangs tools/dev/v8gen.py
  '';

  configurePhase = stdenv.lib.optionalString stdenv.isDarwin ''
    export FORCE_MAC_SDK_MIN=${darwin.apple_sdk.sdk.version}
    substituteInPlace build/mac/find_sdk.py \
        --replace "if not os.path.isdir(sdk_dir) or not '.app/Contents/Developer' in sdk_dir:" \
                  "if False:"
    export PATH=$PATH:${darwin.DarwinTools}/bin
    substituteInPlace build/toolchain/mac/BUILD.gn \
        --replace '&& use_xcode_clang' '|| true'
    substituteInPlace build/config/clang/clang.gni \
        --replace '&& !use_xcode_clang' '&& false'
  '' + ''
    substituteInPlace build/config/compiler/BUILD.gn \
        --replace 'common_optimize_on_ldflags += [ "-Wl,-dead_strip" ]' \
                  'common_optimize_on_ldflags += [ ]'
    substituteInPlace build/config/gcc/BUILD.gn \
        --replace 'cflags_cc = [ "-fvisibility-inlines-hidden" ]' \
                  'cflags_cc = [ ]'
    substituteInPlace build/config/gcc/BUILD.gn \
        --replace 'cflags = [ "-fvisibility=hidden" ]' \
                  'cflags = [ ]'
    tools/dev/v8gen.py -vv ${arch}.release --                   \
      is_component_build=${if static then "false" else "true"}  \
      v8_static_library=${if static then "true" else "false"}   \
      v8_monolithic=${if static then "true" else "false"}       \
      v8_use_external_startup_data=false                        \
      v8_enable_i18n_support=false                              \
      is_clang=true                                             \
      linux_use_bundled_binutils=false                          \
      treat_warnings_as_errors=false                            \
      use_custom_libcxx=false                                   \
      use_custom_libcxx_for_host=false                          \
      clang_use_chrome_plugins=false                            \
      clang_base_path=\"${llvm-packages-v8}\"
  '';

  buildPhase = ''
    ninja -j$NIX_BUILD_CORES -C out.gn/${arch}.release/
  '' +
  (stdenv.lib.optionalString stdenv.isDarwin ''
     for lib in out.gn/${arch}.release/*.dylib; do \
       for i in out.gn/${arch}.release/*.dylib; do \
         export name=$(basename $i); \
         install_name_tool -id $out/lib/$(basename $lib) $lib; \
         install_name_tool -change @rpath/$name $out/lib/$name $lib; \
       done; \
     done
   '');

  installPhase = ''
    install -vD out.gn/${arch}.release/d8 "$out/bin/d8"
    install -vD out.gn/${arch}.release/mksnapshot "$out/bin/mksnapshot"
    mkdir -p "$out/share/v8"
    for f in out.gn/${arch}.release/*.bin; do
        cp -v "$f" "$out/share/v8/"
    done
    mkdir -p "$out/lib"
    for f in out.gn/${arch}.release/obj/*.a; do
        cp -v "$f" "$out/lib/"
    done
    for f in out.gn/${arch}.release/*.dylib; do
        cp -v "$f" "$out/lib/"
    done
    for f in out.gn/${arch}.release/*.so*; do
        cp -v "$f" "$out/lib/"
    done
    for f in out.gn/${arch}.release/obj/third_party/*/*.a; do
        cp -v "$f" "$out/lib/"
    done
    mkdir -p "$out/include"
    cp -vr include/*.h "$out/include"
    cp -vr include/libplatform "$out/include"
  '';

  meta = with lib; {
    description = "Google's open source JavaScript engine";
    maintainers = with maintainers; [ cstrahan proglodyte ];
    platforms = platforms.unix;
    license = licenses.bsd3;
  };
}
