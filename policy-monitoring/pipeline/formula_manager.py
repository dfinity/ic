from pathlib import Path


def formula_local_path(formula_name: str) -> str:
    return str(Path(formula_name).joinpath("formula.mfotl"))
