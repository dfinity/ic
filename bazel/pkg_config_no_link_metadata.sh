#!/usr/bin/env bash
# pkg-config wrapper that strips -L<dir> and -l<lib> tokens from the output.
#
# The rust `pkg_config` crate forces PKG_CONFIG_ALLOW_SYSTEM_LIBS=1, so a
# plain probe of a host library emits the host library dir (e.g.
# -L/usr/lib/x86_64-linux-gnu) as a rustc link-search path. That dir ends up
# in the link line ahead of the hermetic toolchain's library search paths,
# which makes `-lc` resolve to the HOST glibc while the crt objects come from
# the hermetic glibc — an incompatible mix (undefined
# __libc_csu_init/__libc_csu_fini, wrong GLIBC_ symbol versions).
#
# Crates whose annotation sets PKG_CONFIG to this wrapper keep the probe's
# version checks, -I include paths (for bindgen) and -D defines, but emit no
# link metadata; the actual library is linked by explicit path through a
# cc_import dependency instead (see e.g. the devicemapper-sys annotation in
# bazel/rust.MODULE.bazel and third_party/BUILD.devmapper.bazel).

set -euo pipefail

if out="$(pkg-config "$@")"; then
    printf '%s\n' "$out" | sed -E 's/(^| )-[Ll][^ ]*//g'
else
    exit "$?"
fi
