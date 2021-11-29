{ stdenv, fetchgit }:

stdenv.mkDerivation rec {
  pname = "lmdb";
  version = "0.9.26";

  src = fetchgit {
    url = "https://git.openldap.org/openldap/openldap.git";
    rev = "a99290f253a8df45679c8e2b159e83b835e8eb24";
    sha256 = "078948gw896h8blj4dk4638f5jfn14wkyhrvfnbk7xzxlx01plzc";
  };

  postUnpack = "sourceRoot=\${sourceRoot}/libraries/liblmdb";

  outputs = [ "out" "dev" ];

  makeFlags = [
    "prefix=$(out)"
    "CC=${stdenv.cc.targetPrefix}cc"
    "AR=${stdenv.cc.targetPrefix}ar"
  ];

  # Patch to fix read_only DB file permission Other(13) error.
  patches = [
    ./unused_read.patch
    ./debug.patch
  ];
  patchFlags = [ "-p3" ];

  # doCheck = true;
  # checkPhase = "make test";

  # Note we can turn on debug logs from lmdb by adding CFLAGS=\"-DMDB_DEBUG=1\" to build phase
  buildPhase = "make $makeFlags $buildFlags liblmdb.a mdb_dump";

  installPhase = ''
    mkdir -p $out/bin $out/lib $dev/include
    test -f mdb_dump && cp mdb_dump $out/bin/
    test -f liblmdb.a && cp liblmdb.a $out/lib/
    test -f liblmdb.so && cp liblmdb.so $out/lib/
    test -f lmdb.h && cp lmdb.h $dev/include/
    runHook postInstall
  '';

  postInstall =
    # add lmdb.pc (dynamic only)
    ''
      mkdir -p "$dev/lib/pkgconfig"
      cat > "$dev/lib/pkgconfig/lmdb.pc" <<EOF
      Name: lmdb
      Description: ${meta.description}
      Version: ${version}

      Cflags: -I$dev/include
      Libs: -L$out/lib -llmdb -lpthread
      EOF
    '';

  meta = with stdenv.lib; {
    description = "Lightning memory-mapped database";
    longDescription = ''
      LMDB is an ultra-fast, ultra-compact key-value embedded data store
      developed by Symas for the OpenLDAP Project. It uses memory-mapped files,
      so it has the read performance of a pure in-memory database while still
      offering the persistence of standard disk-based databases, and is only
      limited to the size of the virtual address space.
    '';
    homepage = http://symas.com/mdb/;
    maintainers = with maintainers; [ jb55 vcunat ];
    license = licenses.openldap;
    platforms = platforms.all;
  };
}
