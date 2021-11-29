import asyncio
import io
import shlex
import subprocess
import sys
from asyncio.subprocess import PIPE

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


# Run command in a Nix shell, returning stdout
def run_in_nix_shell_quiet(command, shell_nix_path="shell.nix", **kwargs):
    p = subprocess.run(
        ["nix-shell", "--run", command, shell_nix_path],
        check=True,
        capture_output=True,
        **kwargs,
    )
    return p.stdout.rstrip(b"\n")


# Run command in a Nix shell, live dumping the output to stdout and stderr
def run_in_nix_shell(command, shell_nix_path="shell.nix", **kwargs):
    # Subprocess runs with asyncio because we listen
    # on both stdout and stderr at the same time.
    # Without asyncio, we'd risk a deadlock in some cases
    async def nix_run(command, **kwargs):
        process = await asyncio.create_subprocess_exec(
            "nix-shell",
            "--run",
            command,
            shell_nix_path,
            stdout=PIPE,
            stderr=PIPE,
            **kwargs,
        )

        # read child's stdout/stderr concurrently
        buf_out = io.StringIO()
        buf_err = io.StringIO()
        tasks = {
            asyncio.Task(process.stdout.read(1)): (buf_out, process.stdout, sys.stdout),
            asyncio.Task(process.stderr.read(1)): (buf_err, process.stderr, sys.stderr),
        }
        while tasks:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            assert done
            for future in done:
                buf, stream, display = tasks.pop(future)
                line = future.result()
                if line:  # not EOF
                    line = line.decode("utf8")
                    buf.write(line)  # save line for later
                    display.write(line)  # write line to the stdout/stderr
                    # schedule to read the next line
                    tasks[asyncio.Task(stream.read(1))] = buf, stream, display

        rc = await process.wait()
        if rc:
            raise CommandError(command, buf_err.getvalue(), rc)
        return buf_out.getvalue().rstrip("\n")

    return asyncio.run(nix_run(command, **kwargs))


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
