# Here's a set of environment variables that need to be set so crate build scripts pick them up.
# Includes stuff like C library include paths, external tools like libclang and protoc, etc.
# This env is shared between the nix-shell and all of the crate builds in the workspace.
# Specifying these overrides globally, rather than per-crate, which is "technically" cleaner,
# makes the shell evaluate a LOT faster.
{ pkgs }:

let
  inherit (pkgs.stdenv) isDarwin isLinux lib;
  inherit (lib) optionals optionalAttrs;

  lmdb = if isDarwin then pkgs.lmdb else pkgs.lmdb_static;
  rocksdb_static = if isDarwin then pkgs.rocksdb_static else pkgs.rocksdb_static_jemalloc;

  makeCompilerAttrs = stdenv:
    let
      normalize = builtins.replaceStrings [ "-" ] [ "_" ];
      cfg = normalize stdenv.hostPlatform.config;
      inherit (stdenv.cc) targetPrefix;
    in
      {
        "CARGO_TARGET_${lib.toUpper cfg}_LINKER" = "${stdenv.cc}/bin/${targetPrefix}cc";
        "CC_${cfg}" = "${stdenv.cc}/bin/${targetPrefix}cc";
        "CXX_${cfg}" = "${stdenv.cc}/bin/${targetPrefix}c++";
        "AR_${cfg}" = "${stdenv.cc.bintools.bintools}/bin/${targetPrefix}ar";
      };

in
oldAttrs: {
  nativeBuildInputs = (oldAttrs.nativeBuildInputs or []) ++ [
    pkgs.pkgconfig
    pkgs.moc

    pkgs.cmake
    # ar (for cmake)
    pkgs.stdenv.cc.bintools
  ];
  propagatedBuildInputs = (oldAttrs.propagatedBuildInputs or []) ++ [
    lmdb
    pkgs.pkgsStatic.sqlite
  ] ++ optionals isDarwin [
    pkgs.darwin.apple_sdk.frameworks.Security
    pkgs.darwin.apple_sdk.frameworks.CoreServices
    pkgs.darwin.apple_sdk.frameworks.Foundation
    pkgs.darwin.CF
    pkgs.xcbuild
  ];
  propagatedNativeBuildInputs = (oldAttrs.propagatedNativeBuildInputs or []) ++ [
    pkgs.pkgsStatic.libiconv
  ];

  # openssl of course
  OPENSSL_STATIC = true;
  OPENSSL_LIB_DIR = "${pkgs.pkgsStatic.openssl.out}/lib";
  OPENSSL_INCLUDE_DIR = "${pkgs.pkgsStatic.openssl.dev}/include";

  # any crate that uses pkg-config
  PKG_CONFIG = "${pkgs.pkgconfig}/bin/pkg-config";

  # prost-build
  PROTOC = "${pkgs.protobuf}/bin/protoc";
  PROTOC_INCLUDE = "${pkgs.protobuf}/include";

  # bindgen
  LIBCLANG_PATH = "${pkgs.llvmPackages_10.libclang}/lib";
  CLANG_PATH = "${pkgs.llvmPackages_10.clang}/bin/clang";

  # jemalloc
  JEMALLOC_OVERRIDE = "${pkgs.jemalloc_static}/lib/libjemalloc_pic.a";

  # rocksdb
  ROCKSDB_INCLUDE_DIR = "${rocksdb_static}/include";
  ROCKSDB_LIB_DIR = "${rocksdb_static}/lib";
  ROCKSDB_STATIC = true;
  SNAPPY_LIB_DIR = "${pkgs.snappy_static}/lib";
  SNAPPY_STATIC = true;
  LZ4_LIB_DIR = "${pkgs.lz4_static.out}/lib";
  LZ4_STATIC = true;
  ZSTD_LIB_DIR = "${pkgs.zstd_static.out}/lib";
  ZSTD_STATIC = true;
  Z_LIB_DIR = "${pkgs.zlib_static}/lib";
  Z_STATIC = true;
  BZ2_LIB_DIR = "${pkgs.bzip2_static.out}/lib";
  BZ2_STATIC = true;
} // makeCompilerAttrs pkgs.stdenv // optionalAttrs isLinux {
  RUSTFLAGS = "-L${pkgs.gcc9.cc}/lib -Clink-arg=-export-dynamic";
}
