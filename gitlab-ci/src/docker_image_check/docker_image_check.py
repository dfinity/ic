#!/usr/bin/env python3
"""Module to verify that dockerfiles used are the same as those listed in ci/cd files - using sha1 of dockerfiles."""
import glob
import os
import sys

import docker_sha
import git
import yaml


def get_yml_files(searchdir: str):
    """Glob for gitlab ci yml files in a dir, return a list of filenames."""
    globstr = os.path.join(searchdir, "*.yml")
    return glob.glob(globstr)


def validate_docker_image(filepath: str, shalist):
    """Given a gitlab yml filepath and list of sha values determine if all image: name: values end with a valid docker hash."""
    # there may be more than one job in a CI yml file with a docker image
    # if value exists for key, split on '-', and use last value in resulting list for hash lookup
    results = []
    try:
        myfile = open(filepath, "r")
        yaml_dict = yaml.load(myfile, Loader=yaml.FullLoader)
        # example:  looking for yaml_dict['.ubuntu-nix-docker']['image']['name']
        myfile.close()
    except (IOError, ImportError) as err:
        print(f"Problem with {filepath}: {err}")
        raise

    # print(f"\nFile: {filepath}")
    for key in yaml_dict.keys():  # each is a CI Job e.g.  job: image: name:
        # print(f"key: {key}")
        mydict = yaml_dict[key]

        try:
            if type(mydict) != dict:  # some are lists, skip them e.g. 'include:'
                continue
            else:
                if "image" in mydict.keys():
                    value = mydict["image"].get("name", None)
                    # print(f"value: {value}")
                    if not value:  # handles case of empty name value
                        sha = ""
                    elif value in ["dfinity/ic-build:latest", "dfinity/ic-build-nix:latest"]:
                        continue
                    elif "@sha256:" in value:
                        # if the sha256 is specified inline, we can assume it's correct
                        # (otherwise the docker pull would fail anyway)
                        continue
                    else:
                        sha = value.split("-")[-1]  # grab sha1 value from end of image name

                    if sha and sha in shalist:
                        results.append(
                            {
                                "filepath": filepath,
                                "job": key,
                                "status": "success",
                                "sha": sha,
                            }
                        )
                    else:
                        results.append(
                            {
                                "filepath": filepath,
                                "job": key,
                                "status": "fail",
                                "sha": sha,
                            }
                        )
        except Exception as err:
            print(f"Exception occurred parsing yml file for docker image name: {err}")
    return results


def main(args):
    """Do our bidding."""
    git_repo = git.Repo(".", search_parent_directories=True)
    git_root = git_repo.git.rev_parse("--show-toplevel")

    yml_files_location = os.path.join(git_root, "gitlab-ci/config")
    yml_files = get_yml_files(yml_files_location)
    if len(yml_files) == 0:
        print("Did not find any yml files to inspect, exiting")
        sys.exit(1)

    dockerfiles_dict = docker_sha.get_dockerfiles_sha_dict(git_root)
    valid_shas = [dockerfiles_dict[k]["sha"] for k, v in dockerfiles_dict.items()]
    inspected_files = []
    # [ {yml_filepath: fp, job_name: jb, status: success | fail}, ...]
    for yml_file in yml_files:
        try:
            results = validate_docker_image(yml_file, valid_shas)
            # print(results)
            inspected_files += results
        except Exception as err:
            print(f"Error validating image name failed in {yml_file}, {err}")
            sys.exit(1)

    mismatches = 0
    for item in inspected_files:
        if item["status"] == "fail":
            mismatches += 1

    if mismatches:
        print(
            f"\nMismatch in Dockerfiles checked in versus Docker images in CI job. Total {mismatches}"
            "\nDocker image name (sha1 appended) does not match sha1 value of Dockerfile(s)"
        )
        for sha in valid_shas:
            print(f"\nValid SHA: {sha}")
        for myd in inspected_files:
            if myd["status"] == "fail":
                print(
                    f"""\n
                    file: {myd['filepath']}
                    job: {myd['job']}
                    got_sha: {myd['sha']}"""
                )
        print(dockerfiles_dict)
        sys.exit(1)
    else:
        print("All docker images referenced in ci/cd yml have a matching Dockerfile")
        print(dockerfiles_dict)
        sys.exit(0)


if __name__ == "__main__":
    args = sys.argv[1:]
    main(args)

# bogus comment
