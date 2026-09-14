import errno
import os
import stat
import typing

import toml
from integration.github.github_dependency_submission import GHSubDependency, GHSubManifest


def _open_regular_file_nofollow(path: str) -> typing.TextIO:
    """
    Open path for reading, refusing to follow a symlink in the final path component.

    The lock file parsed by this module can originate from an untrusted pull
    request (see .github/workflows/security-checks.yml, which checks out the
    fork's Cargo.Bazel.toml.lock into a pull_request_target job). A fork can
    commit that path as a symlink to an arbitrary file on the CI runner, so
    opening it naively would read whatever the link points at. O_NOFOLLOW makes
    the open itself fail on a symlink, and the fstat check additionally rejects
    anything that is not a regular file. Both happen before any content is read.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        # O_NOFOLLOW reports a symlinked final component as ELOOP (Linux, macOS)
        # or EMLINK (some BSDs); turn that into an explicit refusal so the CI log
        # says why the run failed instead of "too many levels of symbolic links".
        if e.errno in (errno.ELOOP, errno.EMLINK):
            raise RuntimeError(f"Refusing to parse '{path}' because it is a symbolic link") from e
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError(f"Refusing to parse '{path}' because it is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "r")


def parse_bazel_toml_to_gh_manifest(basedir: str, filepath: str) -> GHSubManifest:
    with _open_regular_file_nofollow(os.path.join(basedir, filepath)) as f:
        tree = toml.load(f)

        # direct dependencies in toml files might be either specified by '<name>' or '<name> <version>', e.g.,
        # dependencies = [
        #  "abnf-core",
        #  "nom 7.1.3",
        # ]
        # in order to correctly resolve them, we parse all packages twice
        # first we record all versions for given name and (name, version) for a given '<name> <version>' string
        version_by_name = {}
        name_and_version_by_name_version = {}
        for p in tree["package"]:
            name = p["name"]
            version = p["version"]
            name_version = f"{name} {version}"

            if name not in version_by_name:
                version_by_name[name] = []
            version_by_name[name].append(version)

            if name_version in name_and_version_by_name_version:
                raise RuntimeError(f"Found multiple occurrences of '{name} {version}' in {filepath}")
            name_and_version_by_name_version[name_version] = (name, version)

        # second we resolve all packages and their dependencies using the prepared lookup maps
        resolved = []
        for p in tree["package"]:
            name = p["name"]
            version = p["version"]
            package_url = f"pkg:cargo/{name}@{version}"
            dep_ids = []
            for dep in p.get("dependencies", []):
                if dep in name_and_version_by_name_version:
                    dep_name = name_and_version_by_name_version[dep][0]
                    dep_version = name_and_version_by_name_version[dep][1]
                elif dep in version_by_name and len(version_by_name[dep]) == 1:
                    dep_name = dep
                    dep_version = version_by_name[dep][0]
                else:
                    raise RuntimeError(f"Referenced dependency '{dep}' not found in {filepath}")
                dep_ids.append(f"pkg:cargo/{dep_name}@{dep_version}")
            resolved.append(GHSubDependency(package_url, dep_ids))

        return GHSubManifest(filepath, filepath, resolved)
