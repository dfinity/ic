import os
import random
from typing import Optional


def extract_value(cmd_arg: Optional[str], env_var_name: str) -> Optional[str]:
    if cmd_arg is not None:
        return cmd_arg

    if env_var_name in os.environ:
        return os.environ[env_var_name]

    return None


def extract_value_with_default(cmd_arg: Optional[str], env_var_name: str, default: str) -> str:
    res = extract_value(cmd_arg, env_var_name)
    if res is None:
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
