{ pkgs
, ic-release
, nodemanager
, replica
}:
let
  # We take the version of the replica to be the version of the whole package.
  # inherit (builtins.parseDrvName replica.name) version;
  # TODO: use the above after embedding the replica version in its name
  version = "0.8.0";
in
pkgs.runCommandNoCC "ic-release-package-${version}" {
  nativeBuildInputs = [
    ic-release
    pkgs.jo
  ];
  inherit version nodemanager replica;
} ''
  mkdir -p "$out"

  the_release="ic-release-package-$version.tar.gz"
  the_release_id="ic-release-package-$version-id"

  ic-release \
    --nodemanager-binary "$nodemanager" \
    --replica-binary "$replica" \
    --target-file "$out/$the_release" > "$out/$the_release_id"

  # Creating the manifest
  manifest_file="$out/manifest.json"

  release_sha256hash=($(sha256sum "$out/$the_release")) # using this to autosplit on space
  release_sha1hash=($(sha1sum "$out/$the_release")) # using this to autosplit on space

  release_id_sha256hash=($(sha256sum "$out/$the_release_id")) # using this to autosplit on space
  release_id_sha1hash=($(sha1sum "$out/$the_release_id")) # using this to autosplit on space

  jo -pa \
    $(jo package=ic-release-package \
        version="$version" \
        system="${pkgs.stdenv.system}" \
        name="${pkgs.stdenv.system}/$the_release" \
        file="$out/$the_release" \
        sha256hash="$release_sha256hash" \
        sha1hash="$release_sha1hash") \
    $(jo package=ic-release-package-id \
        version="$version" \
        system="${pkgs.stdenv.system}" \
        name="${pkgs.stdenv.system}/$the_release_id" \
        file="$out/$the_release_id" \
        sha256hash="$release_id_sha256hash" \
        sha1hash="$release_id_sha1hash") > "$manifest_file"

  # Marking the manifest for publishing
  mkdir -p "$out/nix-support"
  echo "upload manifest $manifest_file" >> \
    "$out/nix-support/hydra-build-products"
''
