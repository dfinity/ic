import os


def is_inside_docker() -> bool:
    return os.path.exists("/.dockerenv")
