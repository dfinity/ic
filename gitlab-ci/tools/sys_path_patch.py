import pathlib
import subprocess
import sys

repo_root = pathlib.PosixPath(
    subprocess.check_output(
        "git rev-parse --show-toplevel".split(),
        cwd=pathlib.PosixPath(__file__).absolute().parent,
    )
    .strip()
    .decode("utf8")
)
sys.path.insert(0, str(repo_root / "gitlab-ci" / "src"))
