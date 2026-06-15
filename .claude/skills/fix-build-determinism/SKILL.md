---
name: fix-build-determinism
description: Use this when asked to fix a Bazel build reproducibility / determinism issue — a target whose outputs differ between builds (e.g. across machines, users, or checkout locations), typically because something bakes an absolute build path or a timestamp into an artifact.
---

# Fix build determinism issues

A reproducible build produces byte-identical outputs regardless of *where* it
runs (which directory it's checked out in, which output base, which user). The
IC publishes reproducible artifacts, so any target that bakes a build-time
absolute path, timestamp, or other environment detail into its output is a bug.

The usual culprits are externally-built dependencies — `http_archive`s built
with `rules_foreign_cc` (autotools/cmake) and Rust crates with `build.rs` —
because they escape Bazel's normal path/timestamp scrubbing and can embed
`$PWD`, an install `--prefix`, `__DATE__`/`__TIME__`, a build-script probe
artifact, etc. into their outputs.

All commands run from the repository root (`cd "$(git rev-parse --show-toplevel)"`).

## The `hunt` script

Diagnosis is driven by the upstream `hunt` reproducibility script. It is **not
checked into this repo** — get it from [its gist](https://gist.github.com/nmattia/dc8a1d4f3bc36c9c0133d15f06acc74e), save it
at the repo root as `hunt`, and `chmod +x` it. It builds a target **twice**, each
time in a *freshly cloned* checkout under an output base nested at a **different
depth** — so the absolute build path differs between the two runs the same way
it would differ between two machines. It writes each build's
`--execution_log_json_file` and diffs the `actualOutputs` (path + content
digest) of every action. Any output whose digest differs between the two runs is
a non-reproducible artifact. A clean run ends with `builds 1 - 2: no diff ✓`.

```
usage: ./hunt [--root ROOT] [--startup-options OPTS] [--build-options OPTS] [--runs N] TARGET

  --root ROOT            dir for the per-run checkouts, output bases and execlogs.
                         Default: a fresh `mktemp -d`.
  --startup-options OPTS extra bazel *startup* options, one space-separated string.
  --build-options OPTS   extra bazel *build* options, one space-separated string.
  --runs N               number of builds to compare (default: 2).
  TARGET                 label to build, e.g. //:mkfs.ext4
```

### Always pass `--build-options='--config=local'`

Run with `--build-options='--config=local'`, which builds **without the internal
remote cache** — essential, because a cache hit would serve a previously-built
(possibly non-reproducible) artifact and *mask* the very non-determinism you're
hunting. See the **build-without-dfinity-infra** skill for what `--config=local`
does. (`--startup-options`/`--build-options` are how you feed bazel any other
flags the build needs.)

### Running it

Run `hunt` inside the dev container so the build environment is the pinned one.
See the **run-in-dev-container** skill for how to invoke `container-run.sh`
(including on hosts without podman):

```sh
# quick pass/fail (artifacts land in an ephemeral in-container tempdir):
./ci/container/container-run.sh ./hunt --build-options='--config=local' //my:target

# to *diagnose* (step 3 needs the two builds' outputs to survive the container),
# point --root at a bind-mounted path under /ic so the artifacts persist on the host:
./ci/container/container-run.sh ./hunt --root /ic/,hunt --build-options='--config=local' //my:target
```

Gotchas:
- `hunt` does `git clone` of the repo, so **your fix must be committed** (to the
  current branch) for a hunt run to pick it up. Iterate: commit → hunt → repeat.
- With the default tempdir, the checkouts/output bases live in the container's
  `/tmp` and vanish when the container exits — fine for a verdict, but use
  `--root` under `/ic` when you need to inspect artifacts.
- Bazel marks its output trees read-only. To clean the hunt root between runs:
  `chmod -R u+w <root> && rm -rf <root>`.
- Point `--root` at a path on the same filesystem as the repo for faster
  (hardlinked) clones.

## Procedure

1. **Run `hunt --build-options='--config=local'` on the failing target** and read
   the mismatch JSON it prints — a list of `{path, digest}` for outputs that differed.

2. **Look at the first differing target/output.** Non-determinism cascades: one
   non-reproducible artifact (a generated source, a static lib, a tool binary)
   makes everything that embeds it differ too. Fix the *earliest / most upstream*
   differing artifact first; re-running often makes the downstream diffs vanish.
   Map the output path back to the dependency that produces it (e.g.
   `external/+_repo_rules+<name>/...` → the `http_archive` named `<name>`;
   `external/.../<crate>-<version>/...` → a crate).

3. **Pin down *what* differs.** The execlog only gives digests. Pull the two
   actual artifacts from the persisted output bases (`$ROOT/output-base-1/...`
   vs `$ROOT/output-base-2/...` — use `--root` so these survive) and compare them
   directly:
   ```sh
   cmp "$A" "$B"                                                 # confirm they differ
   diff <(strings -a "$A"|sort -u) <(strings -a "$B"|sort -u)    # build paths / dates
   diff <(readelf -SW "$A") <(readelf -SW "$B")                  # for ELF: which section
   ```
   Typical findings: an embedded absolute build path (`/.../sandbox/.../...`), a
   `__DATE__`/`__TIME__` string, a build-script probe artifact, or archive
   ordering. (Bazel's C toolchain already redacts `__DATE__`/`__TIME__` and
   passes `-no-canonical-prefixes`, so it's almost always an embedded path.)

   From the offending string, settle on a **one-artifact probe** for the bad
   pattern — a command that's non-empty on a broken build and empty once fixed,
   so you can judge a *single* build without re-running the full hunt. Pick the
   most specific stable marker the leak leaves behind (the `sandbox` path
   component, the exec-root / output-base prefix, `.build_tmpdir`, a date, the
   stray probe filename), e.g.:
   ```sh
   strings -a "$A" | grep -n sandbox    # expect matches now; none once fixed
   ```

4. **Read the dependency's source** to find where that string comes from — a
   `configure`-substituted install path, a `build.rs` writing `env!("OUT_DIR")`
   or a `canonicalize()`d path into generated code, a hardcoded `PREFIX/...`
   constant, a stray probe file left in `OUT_DIR`, etc.

5. **Check out the source locally and iterate against it.** Get the dependency at
   the exact version (same `urls`/`sha256` as in `MODULE.bazel`, or the crate
   source), then point Bazel at your local copy so you can edit and rebuild
   without re-uploading a patch each time:
   ```sh
   bazel build --config=local --override_repository=<repo_name>=/abs/path/to/src //my:target
   ```
   (Find `<repo_name>` with `bazel query --output=build <target>` or from the
   execlog path.) Edit, rebuild, and run the step-3 probe on the freshly-built
   artifact as a fast inner-loop check — when it comes back empty the embedded
   dependency is gone:
   ```sh
   strings -a bazel-bin/.../<artifact> | grep sandbox || echo clean
   ```
   This single-build probe is a quick check only; it does **not** replace the
   full reproducibility confirmation in step 8. Keep a pristine copy to `diff`
   against for the patch.

6. **Report it upstream.** A local patch is a workaround — the real fix belongs
   in the dependency, and an upstream fix lets us eventually drop the patch. File
   an issue on the dependency's tracker (for a crate or other GitHub project,
   `https://github.com/<owner>/<repo>/issues/new`), including:
   - a short explanation of the bug and its impact, e.g. *"`build.rs` writes the
     absolute `$OUT_DIR` path into the generated `foo.rs`, so the crate's rlib
     differs between builds at different filesystem locations, breaking
     reproducible/hermetic builds."*
   - a minimal reproducible example if the maintainer will likely need one — the
     smallest snippet that emits the offending output, or simply "build at two
     different paths and `diff` the artifacts" (the step-3 probe doubles as the
     symptom).

   Keep the resulting issue/PR URL; reference it from the patch header below.

7. **Capture the fix as a patch** applied at fetch time (don't fork the dep):

   - **`http_archive` dependency** — add a patch (convention:
     `third_party/<name>_<what>.patch`) and reference it from the archive in
     `MODULE.bazel`:
     ```python
     http_archive(
         name = "<name>",
         ...
         patches = ["//third_party:<name>_<what>.patch"],
         patch_strip = 1,
     )
     ```

   - **Rust crate** — add a patch under `bazel/` and a crate annotation in
     `bazel/rust.MODULE.bazel`:
     ```python
     crate.annotation(
         crate = "<crate-name>",
         patch_args = ["-p1"],
         patches = ["@@//bazel:<crate>.patch"],
     )
     ```

   The patch is a `git diff` (paths `a/…` `b/…`); leading `#` comment lines
   describing the fix — and linking the upstream ticket from step 6 — are fine
   and conventional here. Prefer the smallest patch
   that removes the environment dependency. If the offending artifact is
   something nothing downstream consumes (an extra tool the dependency
   builds/installs), it's also valid to just stop shipping it (e.g. trim it in a
   `rules_foreign_cc` `postfix_script`) rather than make it reproducible.

8. **Re-run `hunt` to confirm** `builds 1 - 2: no diff ✓`. If a *new* (further
   downstream) difference appears, repeat from step 2 — that's the cascade
   resolving one layer at a time. Verify the real consumers of the target still
   build.

## Worked examples

| Dependency | Kind | Cause | Fix | Commit |
| --- | --- | --- | --- | --- |
| **askama** (`bazel/askama.patch`) | crate (derive macro) | `Path::canonicalize()` resolved the sandbox symlink to the repo's real path; the resulting relative path's `..`-count depended on the sandbox path *depth*, so the rlib changed across output-base/nest depths. | Skip `canonicalize()` so both paths stay anchored to the sandbox. | `0d9c593299` (#10167) |
| **rustix** (`bazel/rustix.patch`) | crate (`build.rs`) | The `can_compile()` probe left a `rustix_test_can_compile` artifact in `OUT_DIR`, which rules_rust captures as a cacheable output; it embeds non-deterministic compiler-internal metadata. | Delete the probe artifact after use (upstream PR 1628). | `9f0476004b` (#10353) |
| **libssh2-sys** (`bazel/libssh2-sys.patch`) | crate (`build.rs`) | `build.rs` generated a pkgconfig file containing absolute build paths. | Disable that generation. | `737666659c` (#3197) |
| **e2fsprogs / mke2fs** (`third_party/e2fsprogs_no_external_config.patch`) | `http_archive` (rules_foreign_cc) | `configure`'s `--prefix` is the per-build `$BUILD_TMPDIR`, so the compiled-in `mke2fs.conf` path (`ROOT_SYSCONFDIR`) landed in the binary's `.rodata`. | Empty `config_fn` (use the built-in default profile) + trim the unused, also-non-reproducible extra tools from the install tree. | `cf7fe5147b` |

The askama case is the canonical illustration of *why* `hunt` varies the nest
depth: the bug only manifests when the build path's depth changes between runs.
