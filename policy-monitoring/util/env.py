import os
import random
from typing import Optional

from util.print import eprint


def mask_value_cond(x: str, need_mask: bool) -> str:
    return "[value hidden in logs]" if need_mask else x


def extract_value(cmd_arg: Optional[str], env_var_name: str, secret=True) -> Optional[str]:
    if cmd_arg is not None:
        if env_var_name in os.environ:
            eprint(
                f"CLI option overwrites environment variable for parameter: {env_var_name}={mask_value_cond(cmd_arg, secret)}"
            )
        else:
            eprint(f"Taking parameter value from CLI option: {env_var_name}={mask_value_cond(cmd_arg, secret)}")
        return cmd_arg

    if env_var_name in os.environ:
        res = os.environ[env_var_name]
        eprint(f"Taking parameter value from environment variable: {env_var_name}={mask_value_cond(res, secret)}")
        return res

    eprint(f"Unspecified parameter: {env_var_name}")
    return None


def extract_value_with_default(cmd_arg: Optional[str], env_var_name: str, default: str, secret=True) -> str:
    res = extract_value(cmd_arg, env_var_name, secret)
    if res is None:
        eprint(f"Falling back to default parameter: {env_var_name}={mask_value_cond(default, secret)}")
        return default
    else:
        return res


def generate_signature() -> str:
    return "".join(
        random.sample(
            [
                "a",
                "b",
                "c",
                "d",
                "e",
                "f",
                "g",
                "h",
                "i",
                "j",
                "k",
                "l",
                "m",
                "n",
                "o",
                "p",
                "q",
                "r",
                "s",
                "t",
                "u",
                "v",
                "w",
                "x",
                "y",
                "z",
            ],
            k=13,
        )
    )
