import toml
from integration.github.github_dependency_submission import GHSubDependency, GHSubManifest


def parse_bazel_toml_to_gh_manifest(filename: str) -> GHSubManifest:
    with open(filename, "r") as f:
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
                raise RuntimeError(f"Found multiple occurrences of '{name} {version}' in {filename}")
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
                    raise RuntimeError(f"Referenced dependency '{dep}' not found in {filename}")
                dep_ids.append(f"pkg:cargo/{dep_name}@{dep_version}")
            resolved.append(GHSubDependency(package_url, dep_ids))

        return GHSubManifest(filename, filename, resolved)
