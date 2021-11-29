# This function accepts several arguments
# rname: the name of the release, it will be used to form the name of the artifact as:
#        <rname>-<version>.tar.gz
# version: the version of this release
# files: a list of sets, where each set contains the following keys: "package", "infile", "outfile".
#        "outfile" represents the destination *filename* in the resulting archive. "infile" is the file in
#        the "package" that will be copied. If "outfile" is null, the destination filename will be the same
#        as the input filename. This function does not support copying full directories yet.
{ stdenv, lib, gzip, jo, ic-cdk-optimizer, binaryen }:
rname: version: files:

let
  prezip = stdenv.mkDerivation {
    name = "${rname}-release-pre";
    inherit version;
    phases = [ "buildPhase" ];
    patchLoader = stdenv.isLinux;
    allowedRequisites = [];
    buildPhase = ''
      mkdir -p $out
      copyOptimized() {
        local in=$1
        local dest=$out/$2
        mkdir -p "$(dirname $dest)" || true
        if [[ $in == *.wasm ]]; then
          ${ic-cdk-optimizer}/bin/ic-cdk-optimizer $in \
            --output $dest \
            --wasm-opt-path ${binaryen}/bin/wasm-opt
        else
          cp $in $dest
        fi
        # let's make everything executable for the moment
        chmod 0755 $dest
      }

      ${lib.concatMapStringsSep "\n" (
      entry:
        let
          inf = if entry.infile == null then entry.package else "${entry.package}/${entry.infile}";
        in
          if entry.outfile == null
          then "copyOptimized ${inf} $(basename ${inf})"
          else "copyOptimized ${inf} ${entry.outfile}"
    ) files
    }
    '';
  };
in

stdenv.mkDerivation {
  name = "${rname}-release";
  inherit version;
  phases = [ "buildPhase" ];
  # If `true`, rewrite the interpreter in ELF headers in the tarball to point to /lib64, which is the canonical location for non-NixOS distros.
  patchLoader = stdenv.isLinux;
  buildInputs = [ gzip jo ];
  allowedRequisites = [];
  buildPhase = ''
    # Building the artifacts
    mkdir -p $out
    # we embed the system into the name of the archive
    the_release="${rname}-$version.tar.gz"
    # Assemble the fully standalone archive
    collection=${prezip}

    # The reason why the command below uses 'ls --almost-all' is because we want to avoid
    # storing '.' in the archive. $collection directory is read only, thus if stored,
    # it would hamper proper extraction.
    ls --almost-all "$collection" | tar -cvzf "$out/$the_release" -C "$collection/" -T -

    # Creating the manifest
    manifest_file=$out/manifest.json

    sha256hash=($(sha256sum "$out/$the_release")) # using this to autosplit on space
    sha1hash=($(sha1sum "$out/$the_release")) # using this to autosplit on space

    jo -pa \
      $(jo package="${rname}" \
          version="$version" \
          system="${stdenv.system}" \
          name="${stdenv.system}/$the_release" \
          file="$out/$the_release" \
          sha256hash="$sha256hash" \
          sha1hash="$sha1hash") >$manifest_file

    # Marking the manifest for publishing
    mkdir -p $out/nix-support
    echo "upload manifest $manifest_file" >> \
      $out/nix-support/hydra-build-products

    # Convenience script for helping with ISO installations
    # as we don't have to track changing names
    cat >$out/unpack.sh <<EOF
    #!/usr/bin/env sh
    set -x
    CURRENT_DIR=\$(CDPATH="" cd -- "\$(dirname -- "\$0")" && pwd -P)
    # Check if the archive exists in the same folder as unpack.sh.
    if [ -e "\$CURRENT_DIR/$the_release" ]; then
      tar -xvzf "\$CURRENT_DIR/$the_release" -C \''${1:-.}
    else
      echo >& "Could not find the release file '$the_release' in '\$CURRENT_DIR'."
      exit 1
    fi
    EOF
    chmod a+x $out/unpack.sh
  '';
}
