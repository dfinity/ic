# Builds a script to copy the tarballs of the IC binaries to the
# dfinity-download-public S3 bucket which is the origin of the public
# download.dfinity.systems world-wide CDN.
#
# The tarballs will be published under the following URL scheme:
#
# * https://download.dfinity.systems/ic/<revision>/x86_64-linux/ic-replica.tar.gz
# * https://download.dfinity.systems/ic/<revision>/x86_64-linux/nodemanager.tar.gz
# * https://download.dfinity.systems/ic/<revision>/x86_64-linux/ic-admin.tar.gz
# * https://download.dfinity.systems/ic/<revision>/x86_64-darwin/ic-admin.tar.gz
#
# This script will be automatically and periodically executed by DFINITY's
# Continuous Deployment system. That system will also set the correct AWS
# credentials and the DFINITY_DOWNLOAD_BUCKET environment variable. The above is
# configured in:
# https://github.com/dfinity-lab/infra/blob/master/services/nix/configuration-deployer.nix
#
# To publish the IC from your machine make sure that the environment variables
# DFINITY_DOWNLOAD_DOMAIN and DFINITY_DOWNLOAD_BUCKET are set and that you have
# access to the dfinity-download-public S3 bucket. Then run:
#
#   nix run -f . publish.ic -c activate
#
{ pkgs, jobset, rev }:
let
  s3cp = pkgs.lib.writeCheckedShellScriptBin "s3cp" [] ''
    set -eu
    PATH="${pkgs.lib.makeBinPath [ pkgs.awscli ]}"
    src="$1"; dst="$2"; contentType="$3"; cacheControl="$4"
    dstUrl="s3://$DFINITY_DOWNLOAD_BUCKET/$dst"
    if [ -d "$src" ]; then
      echo "Can't copy $src to $dstUrl because it's a directory. Please specify a file instead." 1>&2; exit 1;
    fi
    echo "Uploading $src to $dstUrl (--cache-control $cacheControl, --content-type $contentType)..."
    aws s3 cp "$src" "$dstUrl" \
      --cache-control "$cacheControl" \
      --no-guess-mime-type --content-type "$contentType" \
      --no-progress
  '';
in
pkgs.lib.linuxOnly (
  pkgs.lib.writeCheckedShellScriptBin "activate" [] ''
    set -eu
    PATH="${pkgs.lib.makeBinPath [ s3cp ]}"

    cache_long="max-age=31536000" # 1 year

    dir="ic/${rev}"

    ic_version="0.8.0"

    s3cp "${jobset.dfinity.rs.ic-replica-release.x86_64-linux}/ic-replica-$ic_version.tar.gz" \
         "$dir/x86_64-linux/ic-replica.tar.gz" \
         "application/gzip" "$cache_long"
    s3cp "${jobset.dfinity.rs.nodemanager-release.x86_64-linux}/nodemanager-$ic_version.tar.gz" \
         "$dir/x86_64-linux/nodemanager.tar.gz" \
         "application/gzip" "$cache_long"
    s3cp "${jobset.dfinity.rs.ic-admin-release.x86_64-linux}/ic-admin-$ic_version.tar.gz" \
         "$dir/x86_64-linux/ic-admin.tar.gz" \
         "application/gzip" "$cache_long"
    s3cp "${jobset.dfinity.rs.ic-admin-release.x86_64-darwin}/ic-admin-$ic_version.tar.gz" \
         "$dir/x86_64-darwin/ic-admin.tar.gz" \
         "application/gzip" "$cache_long"
  ''
)
