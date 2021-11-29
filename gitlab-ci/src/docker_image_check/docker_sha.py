#!/usr/bin/env python3
"""Script to obtain the sha1 of GitLab CI dockerfiles."""
import argparse
import hashlib
import os
import sys
from os.path import abspath
from os.path import dirname

# DO NOT import any external Python packages. This script must run on the
# protected runners which has only a minimal Python installation.


def _read_file(filepath: str) -> bytes:
    """Return the contents of a file."""
    try:
        # print(f"Filepath: {filepath}")
        myfile = open(filepath, "rb")
        newstr = myfile.read()
        myfile.close()
        return newstr
    except IOError as err:
        print(f"IOError Exception raised getting sha1: {err}")
        raise
    except Exception as err:
        print(f"Exception raised getting sha1: {err}")
        raise


def _get_dockerfile_contents(filepaths_list, search_path) -> str:
    # Given a list of filepaths, create a concatenation of each file's contents
    # and return the result as a string
    result = b""
    for filename in filepaths_list:
        content = _read_file(os.path.join(search_path, filename))
        result += content
    return result


def _get_sha1(newstr: bytes) -> str:
    """Return the sha1 value of a file."""
    # change newstr to accept bytes
    try:
        result = hashlib.sha1(newstr)
        return result.hexdigest()
    except IOError as err:
        print(f"IOError Exception raised getting sha1: {err}")
        raise
    except Exception as err:
        print(f"Exception raised getting sha1: {err}")
        raise


def get_dockerfiles_sha_dict(git_root: str) -> dict:
    # Generate sha values for dockerfiles
    dockerfiles_dict = {
        "Dockerfile": {"files": ["Dockerfile"], "sha": None},
        "Dockerfile.withnix": {
            "files": ["Dockerfile", "Dockerfile.withnix"],
            "sha": None,
        },
    }
    search_path = os.path.join(git_root, "gitlab-ci", "docker")
    for _, dvalue in dockerfiles_dict.items():
        try:
            # get concat string of file
            dockerfile_content = _get_dockerfile_contents(dvalue["files"], search_path)

            # generate sha
            sha1 = _get_sha1(dockerfile_content)

            # store data into dockerfiles_dict
            dvalue.update({"sha": sha1})

        except Exception as err:
            print(f"Unable to generate sha1 value for {dvalue}, exiting")
            print(f"Exception: {err}")
            sys.exit(1)

    return dockerfiles_dict


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "dockerfile",
        type=str,
        help="Dockerfile to compute SHA1 either 'Dockerfile' or 'Dockerfile.withnix'",
    )
    args = parser.parse_args()

    #
    repo_root = dirname(dirname(dirname(dirname(abspath(__file__)))))

    dockerfiles_dict = get_dockerfiles_sha_dict(repo_root)
    if args.dockerfile in dockerfiles_dict.keys():
        sha1 = dockerfiles_dict[args.dockerfile]["sha"]
        print(f"{sha1}")
        sys.exit(0)
    else:
        print(f"Unable to generate sha for {args.dockerfile}")
        sys.exit(1)


if __name__ == "__main__":
    main()
