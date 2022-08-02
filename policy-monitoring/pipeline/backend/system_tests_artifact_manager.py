from pathlib import Path


class SystemTestsArtifactManager:
    def __init__(self, working_dir: str):
        self.working_dir = Path(working_dir)

    def test_driver_log_path(self) -> Path:
        return self.working_dir.joinpath("system_env", "test.log")

    def registry_snapshot_path(self, pot_name: str) -> Path:
        return self.working_dir.joinpath(pot_name, "setup", "ic_prep", "initial_registry_snapshot.json")
