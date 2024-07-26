import shlex
import subprocess

import yaml


# Run command directly, without invoking a shell
def run(command, **kwargs):
    return (
        subprocess.run(shlex.split(command), capture_output=True, check=True, **kwargs)
        .stdout.decode("utf8")
        .rstrip("\n")
    )


# Run in a shell
def run_in_shell(command, **kwargs):
    return (
        subprocess.run(command, capture_output=True, check=True, shell=True, **kwargs)
        .stdout.decode("utf8")
        .rstrip("\n")
    )


def yaml_dump_sorted_without_anchors(data):
    class NoAliasDumper(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    return yaml.dump(data, Dumper=NoAliasDumper, sort_keys=True)


class CommandError(Exception):
    """Exception raised during command execution."""

    def __init__(self, command, stderr, returncode):
        """Create a CommandError from a command execution results."""
        self.command = command
        self.stderr = stderr
        self.returncode = returncode
        super().__init__(self.command, self.stderr, self.returncode)

    def __str__(self):
        """Convert the CommandError to the string representation."""
        return f"Failed execution (rc={self.returncode}); STDERR:\n" + str(self.stderr)
