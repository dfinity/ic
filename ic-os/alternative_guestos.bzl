def _download_alternative_guestos_proposal_impl(ctx):
    output = ctx.actions.declare_file(ctx.label.name)

    command = """
set -euo pipefail

proposal_id="$(cat {proposal_id_file})"

if [[ -z "$proposal_id" ]]; then
  echo "//{package}:{name} requires ALTERNATIVE_GUESTOS_PROPOSAL_ID to be set in the environment before invoking Bazel." >&2
  exit 1
fi

{tool} download-signed-proposal \
  --proposal-id "$proposal_id" \
  --nns-url {nns_url} \
  --output {output}
""".format(
        name = ctx.label.name,
        nns_url = ctx.attr.nns_url,
        output = output.path,
        package = ctx.label.package,
        proposal_id_file = ctx.file._proposal_id_file.path,
        tool = ctx.executable._tool.path,
    )

    ctx.actions.run_shell(
        command = command,
        inputs = [ctx.file._proposal_id_file],
        outputs = [output],
        tools = [ctx.attr._tool.files_to_run],
        mnemonic = "DownloadAlternativeGuestosProposal",
    )

    return [DefaultInfo(files = depset([output]))]

download_alternative_guestos_proposal = rule(
    implementation = _download_alternative_guestos_proposal_impl,
    attrs = {
        "nns_url": attr.string(default = "https://ic0.app"),
        "_proposal_id_file": attr.label(
            allow_single_file = True,
            default = Label("//bazel:alternative_guestos_proposal_id.txt"),
        ),
        "_tool": attr.label(
            default = Label("//rs/ic_os/build_tools/alternative_guestos"),
            executable = True,
            cfg = "exec",
        ),
    },
)

# Creates a tarball containing the bootfs file tree extracted from a released GuestOS.
def prepare_alternative_guestos_base_bootfs_tree_tar(name, out, tags = None, target_compatible_with = None):
    native.genrule(
        name = name,
        srcs = ["//bazel:alternative_guestos_base_version.txt"],
        outs = [out],
        cmd = """
set -euo pipefail

base_version="$$(cat $<)"

if [[ -z "$$base_version" ]]; then
  echo "//{package}:{name} requires ALTERNATIVE_GUESTOS_BASE_VERSION to be set in the environment before invoking Bazel." >&2
  exit 1
fi

tmpdir="$$(mktemp -d)"
mounted=0
cleanup() {{
  set +e
  if [[ "$$mounted" -eq 1 ]]; then
    fusermount3 -u "$$tmpdir/bootfs" || fusermount -u "$$tmpdir/bootfs" || umount "$$tmpdir/bootfs"
  fi
  rm -rf "$$tmpdir"
}}
trap cleanup EXIT

curl --fail --silent --show-error --location \
  "https://download.dfinity.systems/ic/$$base_version/guest-os/update-img/update-img.tar.zst" \
  | tar --extract --zstd --to-stdout --file - boot.img > "$$tmpdir/boot.img"

mkdir "$$tmpdir/bootfs"
$(location //:fuse2fs) -o ro,norecovery,fakeroot "$$tmpdir/boot.img" "$$tmpdir/bootfs"
mounted=1
tar --create --file "$@" --numeric-owner -C "$$tmpdir/bootfs" .
""".format(
            name = name,
            package = native.package_name(),
        ),
        message = "Downloading alternative GuestOS base boot image and converting it to tar via fuse2fs",
        tags = tags,
        target_compatible_with = target_compatible_with,
        tools = ["//:fuse2fs"],
    )
