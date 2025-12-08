import logging
import os
import shlex
import subprocess
import typing
from pathlib import Path


class ProcessExecutor:
    def __init__(self, command):
        self.command = command

    @staticmethod
    def execute_command(
        command: str,
        cwd: Path,
        environment: typing.Dict[str, str],
        ignore_return_code_if_stdout_is_set: bool = False,
        log_error_on_fail: bool = True,
        log_command: bool = True,
    ) -> str:
        environ = dict(os.environ)
        environ.update(environment)
        if log_command:
            logging.info("Executing : " + command)
        command = shlex.split(command)
        result = subprocess.run(command, cwd=cwd, encoding="utf-8", capture_output=True, text=True, env=environ)

        if result.returncode > 1 and not (ignore_return_code_if_stdout_is_set and len(result.stdout) > 0):
            if log_error_on_fail:
                if log_command:
                    logging.error("Process Executor failed for " + str(command))
                else:
                    logging.error("Process Executor failed")
                logging.debug(result.stderr)
                logging.debug(result.stdout)
            raise subprocess.CalledProcessError(result.returncode, command, result.args, result.stderr)
        else:
            if log_command:
                logging.info("Process Executor succeeded for " + str(command))
            else:
                logging.info("Process Executor succeeded")
            logging.debug(result.stderr)
            return result.stdout.strip()
