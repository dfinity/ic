# This file holds the `DfinityGitLabConfig` class, which provides an abstraction
# of the GitLab CI configuration.
# For instance, it provides public functions to:
# - load the CI configuration from a Yaml string
# - load the CI configuration from a file
# - lint the CI configuration
# In the future, other functionality may be added.
#
# Typical usage:
#     gl_cfg = dfinity_gitlab_config.DfinityGitLabConfig()
#     gl_cfg.ci_cfg_load(cfg)
#     gl_cfg.ci_cfg_lint()
# These commands:
# 1. Load the CI config from the Yaml file,
# 2. Recursively load all included files, replacing the 'include' statements with the file contents,
# 3. Recursively expand all "extends" statements, replacing them with the pointed-to contents,
# 4. Send the resulting Yaml config to the GitLab CI Yaml validation service,
# 5. Lint the job script (before_script + script + after_script) with `shellcheck`
#
import copy
import logging
import os
import pathlib
import shutil
import subprocess
import tempfile
import urllib
from multiprocessing import Pool
from typing import TextIO

import git
import gitlab  # type: ignore
import yaml

from gitlab_config import utils

GITLAB_URL = "https://gitlab.com"
GITLAB_PROJECT_ID = urllib.parse.quote_plus("25333072")


# TODO: this is likely a very poor escape. We should do here exactly the same as GitLab.
def escape_yaml(content):
    """Replace double dollar signs with single to unquote YAML strings."""
    if isinstance(content, str):
        return content.replace("$$", "$").replace(r'"', r"\"")
    else:
        return content


class DfinityGitLabConfig:
    """Interface with the GitLab clone of the DFINITY monorepo."""

    def __init__(self, repo_root_local=None):
        """Initialize a GitLab repo with the provided local repo clone."""
        if repo_root_local:
            self._repo_root_local = pathlib.Path(repo_root_local)
        else:
            # Use the "git" module to find the root of the repo to which this file belongs
            git_repo = git.Repo(__file__, search_parent_directories=True)
            git_root = git_repo.git.rev_parse("--show-toplevel")
            self._repo_root_local = pathlib.Path(git_root)
        self.gitlab_url = GITLAB_URL
        self.proj_id = GITLAB_PROJECT_ID
        if "GITLAB_API_TOKEN" not in os.environ:
            raise ValueError("Fatal: GITLAB_API_TOKEN env var not set")
        self._gl = gitlab.Gitlab(self.gitlab_url, private_token=os.environ.get("GITLAB_API_TOKEN"))
        self.ci_cfg = {}
        self.ci_cfg_expanded = {}
        self._ci_cfg_included_file_list = []

    def ci_cfg_reset(self):
        """Reset/clear the CI config."""
        self.ci_cfg = {}
        self.ci_cfg_expanded = {}
        self._ci_cfg_included_file_list = []

    def _ci_cfg_get_keys(self, ci_config: dict):
        result = []

        for job_name, job in ci_config.items():
            if isinstance(job, dict):
                # Regular job is always a dict and has a "script field"
                # `stages`, for example, is a list
                result.append(job_name)
        return result

    def ci_cfg_jobs(self):
        """Return a list of all jobs defined in the CI configuration."""
        if self.ci_cfg_expanded:
            return [x for x in self._ci_cfg_get_keys(self.ci_cfg_expanded) if "script" in self.ci_cfg_expanded[x]]
        return []

    def ci_cfg_jobs_in_stage(self, stage: str):
        """Return a list of all jobs from a particular stage."""
        return [job_name for job_name in self.ci_cfg_jobs() if self.ci_cfg_expanded[job_name]["stage"] == stage]

    def ci_cfg_jobs_divided_to_stages(self):
        """Return a list of all jobs, divided into stages."""
        result = {}
        for stage in self.ci_cfg_expanded.get("stages", []):
            result[stage] = self.ci_cfg_jobs_in_stage(stage)
        return result

    def ci_cfg_load(self, content: str):
        """
        Load the CI configuration from a string.

        There are two stages to loading:
        1. Load the root yaml file, find 'include' and replace them with included file
           contents. The results of this stage are stored in `self.ci_cfg`.
        2. For each job defined in `self.ci_cfg` expand all "extends" statements and build
           complete job descriptions. The results of this stage are stored in `self.ci_cfg_expanded`.

        Note: may be invoked multiple times to merge multiple CI config files.
        """
        if not isinstance(content, str):
            raise ValueError("content argument must be of str type")

        ci_cfg = yaml.load(content, Loader=yaml.FullLoader)

        # Included files may also have included files, so we may need several passes to
        # get all includes recursively
        includes = self._ci_cfg_extract_included_files(ci_cfg)
        max_depth = 0
        while includes and max_depth < 100000:
            max_depth += 1
            for i in includes:
                include_file_name = self._repo_root_local / i[1:]  # omit the leading /
                self._ci_cfg_included_file_list.append(include_file_name)
                incl_cfg = yaml.load(open(include_file_name), Loader=yaml.FullLoader)
                ci_cfg = self._merge_job_dicts(incl_cfg, ci_cfg)
            includes = self._ci_cfg_extract_included_files(ci_cfg)

        if self.ci_cfg:
            # Merge the existing config with the newly loaded
            ci_cfg = self._merge_job_dicts(ci_cfg, self.ci_cfg)

        self.ci_cfg = ci_cfg

        # Expand all templates and 'extends' statements in CI job config.
        self._ci_cfg_jobs_expand_extends(ci_cfg)

    def ci_cfg_load_from_file(self, file: TextIO):
        """Load the CI configuration from a file."""
        return self.ci_cfg_load(file.read())

    def ci_cfg_included_files(self):
        """Return a list of the files which make up the CI config."""
        return self._ci_cfg_included_file_list

    def ci_cfg_lint(self, verbose=True):
        """Lint the CI configuration that was already loaded earlier."""
        if not self.ci_cfg_expanded:
            raise ValueError("No CI config. Please use ci_cfg_load or ci_cfg_load_from_file to load config.")
        self._ci_cfg_lint_with_job_name_linter(verbose)
        self._ci_cfg_lint_with_bash_linter(verbose)
        return self._ci_cfg_lint_with_gitlab_linter()

    def ci_cfg_get_job(self, job_name: str):
        """Generate the CI config for the provided job_name."""
        return self.ci_cfg_expanded.get(job_name, {})

    def ci_cfg_get_job_set_push(self, job_name: str):
        """Return the CI config for the job, and set the run rules to execute on push."""
        job_config = self.ci_cfg_get_job(job_name)
        if job_config and isinstance(job_config, dict):
            job_config["rules"] = [{"if": '$CI_PIPELINE_SOURCE == "push"'}]
        return job_config

    def ci_cfg_patch_job_cfg_add(self, job_cfg_patch: dict):
        """Patch CI configs by adding the provided job_cfg_path."""
        for job_name, job in self.ci_cfg.items():
            if isinstance(job, dict):
                self.ci_cfg[job_name] = self._merge_job_dicts(job_cfg_patch, job)

    def ci_cfg_get_job_script(self, job_name: str):
        """Generate the shell script which would execute for the provided job_name."""
        if job_name not in self.ci_cfg_expanded:
            return
        job = self.ci_cfg_expanded[job_name]
        before_script = job.get("before_script", [])
        if isinstance(before_script, list):
            before_script = "\n".join(before_script)
        script = job.get("script", [])
        if isinstance(script, list):
            script = "\n".join(script)
        after_script = job.get("after_script", [])
        if isinstance(after_script, list):
            after_script = "\n".join(after_script)
        return "\n".join([before_script, script, after_script])

    def _ci_cfg_extract_included_files(self, cfg_file: dict):
        include_files = []
        for k in list(cfg_file.keys()):
            if k == "include":
                inc = cfg_file[k]
                if isinstance(inc, str):
                    logging.debug("included local file: %s", inc)
                    include_files.append(inc)
                elif isinstance(inc, list):
                    for include in inc:
                        for t, uri in include.items():
                            if t == "local":
                                logging.debug("include local file from a list: %s", uri)
                                include_files.append(uri)
                            else:
                                logging.warning("unsupported include type: %s ==> URI %s", t, uri)
                del cfg_file["include"]
        logging.debug("found included files: %s", include_files)
        return include_files

    def _ci_cfg_jobs_with_extends(self, ci_config: dict):
        return [x for x in self._ci_cfg_get_keys(ci_config) if "extends" in ci_config[x]]

    def _ci_cfg_inject_before_after_script(self, ci_config: dict, job_name: str):
        # This function injects the "before_script" and "after_script" for the job,
        # if they are defined somewhere in the CI configuration.
        # "before_script" can be either at a global level or within "default"
        # https://docs.gitlab.com/ee/ci/yaml/#before_script
        # Globally defined "before_script" and "after_script" is deprecated
        # https://docs.gitlab.com/ee/ci/yaml/#globally-defined-image-services-cache-before_script-after_script
        # but still valid syntax.
        #
        job = ci_config[job_name]
        if "script" in job:
            # "before_script" and "after_script" aren't valid without "script"
            before_script = None
            if "before_script" in ci_config:
                before_script = ci_config["before_script"]
            if "default" in ci_config and "before_script" in ci_config["default"]:
                before_script = ci_config["default"]["before_script"]
            if before_script is not None:
                if "before_script" not in job:
                    job["before_script"] = before_script
            after_script = None
            if "after_script" in ci_config:
                after_script = ci_config["after_script"]
            if "default" in ci_config and "after_script" in ci_config["default"]:
                after_script = ci_config["default"]["after_script"]
            if after_script is not None:
                if "after_script" not in job:
                    job["after_script"] = after_script
        return ci_config

    def _ci_cfg_jobs_expand_extends(self, ci_config: dict):
        # This function replaces the "extends" key with the contents pointed to.
        # This is necessary since the GitLab CI validation API does not properly support
        # the "extends" keyword.
        # And also we want to lint the resulting shell scripts for all jobs, to improve our
        # confidence in the CI configuration.

        ci_config = copy.deepcopy(ci_config)
        jobs = self._ci_cfg_jobs_with_extends(ci_config)

        max_depth = 0
        while jobs and max_depth < 100000:
            max_depth += 1

            for job_name in jobs:
                job = ci_config[job_name]
                if "extends" in job:
                    job_parent_name = job["extends"]
                    if isinstance(job_parent_name, str):
                        job_parent = ci_config[job_parent_name]
                        if "extends" in job_parent:
                            # Only merge with parents that are already fully merged
                            continue
                        job_new = self._merge_job_dicts(job, job_parent)
                        del job_new["extends"]
                        ci_config[job_name] = job_new
                    elif isinstance(job_parent_name, list):
                        job_new = job
                        # parents are `reversed` because jobs later in the list overwrite earlier ones
                        # so if the same key is present in a later and earlier job, the later one
                        # will take preference
                        parents_have_extends = False
                        for p in reversed(job_parent_name):
                            job_parent = ci_config[p]
                            if "extends" in job_parent:
                                # Only merge with parents that are already fully merged
                                parents_have_extends = True
                                break
                            job_new = self._merge_job_dicts(job_new, job_parent)
                        if parents_have_extends:
                            # Only merge with parents that are already fully merged
                            continue
                        del job_new["extends"]
                        ci_config[job_name] = job_new
                    else:
                        logging.warning("unsupported extends type: %s ", job_parent_name)
            jobs = self._ci_cfg_jobs_with_extends(ci_config)

        self.ci_cfg_expanded = self._ci_cfg_jobs_remove_templates(ci_config)

        for job_name in self.ci_cfg_jobs():
            # Inject the `before_script` and `after_script`, if available
            self._ci_cfg_inject_before_after_script(ci_config, job_name)

        return ci_config

    def _ci_cfg_jobs_remove_templates(self, ci_config: dict):
        for entry in list(ci_config.keys()):
            if entry.startswith("."):
                del ci_config[entry]
        return ci_config

    def _ci_cfg_lint_with_gitlab_linter(self):
        content = yaml.dump(self.ci_cfg, indent=2)

        data = {"content": content, "dry_run": False}
        logging.debug("Linting CI config at the GitLab CI API: %s", data)

        # Validate a gitlab CI configuration with a namespace.
        result = self._gl.http_post(
            f"{self.gitlab_url}/api/v4/projects/{self.proj_id}/ci/lint",
            post_data=data,
        )

        if result["errors"] or result["warnings"]:
            logging.error("Content for validation:\n%s", content)
            raise ValueError(result["errors"] + result["warnings"])

        if not result["valid"]:
            # No errors or warnings reported, but the result is still not valid.
            # Not sure if this may happen or not, but still let's be on the safe side
            raise ValueError("Validation failed")
        logging.debug("CI config linted using the GitLab CI Lint API https://docs.gitlab.com/ee/api/lint.html")

    def _bash_linter(self, job_name, content):
        if shutil.which("shellcheck"):
            # shellcheck is already in path, use it
            def shellcheck(path):
                try:
                    return utils.run(f"shellcheck --shell=bash {path}")
                except subprocess.CalledProcessError as e:
                    logging.error(e.output.decode())
                    raise

        else:
            # run in a new nix-shell
            nix = pathlib.PurePath(__file__).parent.parent.joinpath("shell.nix").as_posix()

            def shellcheck(path):
                return utils.run_in_nix_shell(f"shellcheck --shell=bash {path}", shell_nix_path=nix)

        (_, path) = tempfile.mkstemp(suffix=f"-{job_name}")
        with open(path, "w") as f:
            f.write(content)
            f.close()
        shellcheck(path)
        os.unlink(path)

    def ci_job_script(self, job_name: str):
        """Dump the script generated for the provided job_name."""
        job = self.ci_cfg_expanded[job_name]
        before_script = job.get("before_script", [])
        if isinstance(before_script, list):
            before_script = "\n".join(before_script)
        script = job.get("script", [])
        if isinstance(script, list):
            script = "\n".join(script)
        after_script = job.get("after_script", [])
        if isinstance(after_script, list):
            after_script = "\n".join(after_script)
        vars = "\n".join([f'export {k}="{escape_yaml(v)}"' for k, v in job.get("variables", {}).items()])
        return """\
######################################################
# CI variables
######################################################
{vars}

######################################################
# Simulation environment variables
######################################################
test -n "${{SHELL_WRAPPER_SIMULATED:-}}" && export SHELL_WRAPPER=$SHELL_WRAPPER_SIMULATED
export CI_JOB_STAGE="{job_stage}"
export CI_JOB_NAME="{job_name}"
export CI_PIPELINE_SOURCE="manual"
export CI_PIPELINE_ID="100000"
export CI_JOB_ID="100000000000"

# A parent pipeline sets these variables, but they are consumed by jobs in a
# child pipeline. Therefore, make sure they are always exported before the bash
# linter checks the job configurations, otherwise it will assume these variables
# do not exist.
export TESTNET="testnet"
export TESTNET1="testnet1"
export TESTNET2="testnet2"
export TESTNET3="testnet3"
export TESTNET4="testnet4"
export TESTNET5="testnet5"
function shell_wrapper_simulated() {{
   echo "$@" | tee -a "$JOB_RESULT_FILE"
}}

######################################################
# before_script
######################################################
{before_script}

######################################################
# script
######################################################
{script}

######################################################
# after_script
######################################################
{after_script}

exit 0
""".format(
            vars=vars,
            job_stage=job["stage"],
            job_name=job_name,
            before_script=before_script,
            script=script,
            after_script=after_script,
        )

    def _ci_cfg_lint_with_job_name_linter(self, verbose=False):
        if verbose:
            log = logging.info
        else:
            log = logging.debug

        errors = []
        for job_name in self.ci_cfg_jobs():
            log("linting '%s' with job name linter", job_name)
            if " " in job_name or "\t" in job_name:
                errors.append(f"Job '{job_name}' should not contain whitespace; use a hyphen")

        if errors:
            raise ValueError("\n".join(errors))

    def _bash_lint_job(self, job_name: str):
        logging.info("linting job '%s' with bash linter", job_name)
        return self._bash_linter(job_name, self.ci_job_script(job_name))

    def _ci_cfg_lint_with_bash_linter(self, verbose=False):
        if verbose:
            log = logging.info
        else:
            log = logging.debug

        def bash_lint_default_section(section):
            if section in self.ci_cfg_expanded:
                log("linting '%s' with bash linter", section)
                contents = "\n".join(self.ci_cfg_expanded[section])
                self._bash_linter(section, contents)
            if "default" in self.ci_cfg_expanded and section in self.ci_cfg_expanded["default"]:
                log("linting 'default: %s' with bash linter", section)
                contents = "\n".join(self.ci_cfg_expanded["default"][section])
                self._bash_linter(section, contents)

        bash_lint_default_section("before_script")
        bash_lint_default_section("after_script")

        with Pool(32) as p:
            # run bash_lint_job(job_name), for all jobs
            p.map(self._bash_lint_job, self.ci_cfg_jobs())

        logging.debug("bash linter done")

    def ci_job_simulate(self, job_name: str):
        """
        Simulate the job execution, in a weakly isolated bash shell.

        Returns the lines from the job script which start with $SHELL_WRAPPER, if the script execution succeeded.
        If the script execution fails for any reason, throws an exception.

        Note: This function is not yet enabled in the CI checks.
        """
        chroot = tempfile.mkdtemp()

        job = self.ci_cfg_expanded[job_name]
        if "SHELL_WRAPPER" not in job["variables"]:
            raise ValueError("Job environment variable 'SHELL_WRAPPER' is not set.")

        # Save the job script, to be invoked later
        job_script_path = chroot + "/job.sh"
        with open(job_script_path, "w") as f:
            logging.debug("Job sim [%s]: written script to %s", job_name, job_script_path)
            f.write(self.ci_job_script(job_name))

        if not os.path.exists(chroot + "/key"):
            # Remove any possible remnants of the ssh key
            logging.debug("Job sim [%s]: generating ssh key", job_name)
            if os.path.exists(chroot + "/key"):
                shutil.rmtree(chroot + "/key")
            if os.path.exists(chroot + "/key.pub"):
                shutil.rmtree(chroot + "/key.pub")
            utils.run(f"ssh-keygen -t ed25519 -f '{chroot}/key' -N ''")

        # Save the original path
        orig_path = os.getcwd()

        os.chdir(self._repo_root_local)
        CI_COMMIT_SHA = utils.run("git rev-parse HEAD")

        # Clone the repo
        tgt_repo_path = f"{chroot}/dfinity"
        if os.path.exists(tgt_repo_path):
            logging.debug("Job sim [%s]: remove existing repo at %s", job_name, tgt_repo_path)
            shutil.rmtree(tgt_repo_path)
        logging.debug("Job sim [%s]: clone repo to %s", job_name, tgt_repo_path)
        utils.run(f"git clone {self._repo_root_local} {tgt_repo_path}")

        # CD into the cloned repo
        os.chdir(tgt_repo_path)
        logging.debug("Job sim [%s]: check out %s", job_name, CI_COMMIT_SHA)
        utils.run(f"git checkout --detach --force {CI_COMMIT_SHA}")

        # Ensure the empty job-result.txt
        job_result_file = f"{chroot}/job-result.txt"
        if os.path.exists(job_result_file):
            os.remove(job_result_file)

        env = {
            "HOME": chroot,
            "CI_PROJECT_DIR": tgt_repo_path,
            "SSH_PRIVATE_KEY": open(chroot + "/key").read(),
            "CI_COMMIT_SHA": CI_COMMIT_SHA,
            "CI_JOB_ID": "10000010010",
            "TESTNET": "real-testnet-goes-here",
            "SHELL_WRAPPER_SIMULATED": "shell_wrapper_simulated",
            "JOB_RESULT_FILE": job_result_file,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }

        try:
            logging.debug("running with env %s", env)
            # run the job script
            utils.run_in_shell(f"bash {chroot}/job.sh >{chroot}/job.out 2>{chroot}/job.err", env=env)
        except subprocess.CalledProcessError as e:
            env_shell = "\n".join([f"export {k}='{v}'" for k, v in env.items()])
            logging.error(
                "Execution failed OUT:%s ERR:%s RC:%d. "
                "The output is preserved in %s (take a look at job.out and job.err). "
                "To reproduce run:\n"
                "env -i bash --noprofile --norc\n"
                "%s\n"  # env
                "cd $HOME && bash ./job.sh",
                e.stdout,
                e.stderr,
                e.returncode,
                chroot,
                env_shell,
            )
            raise

        # return to the original path
        os.chdir(orig_path)

        result = open(job_result_file).read()

        shutil.rmtree(chroot)

        return result

    def _merge_job_dicts(self, source, destination):
        """
        Merge the "source" and "destination" job dictionaries.

        Destination is extended with all entries from source.
        If a key in destination already exists, it is replaced by the key with the same name from source.
        Based on:
        https://stackoverflow.com/questions/20656135/python-deep-merge-dictionary-data
        run me with nosetests --with-doctest file.py
        """
        if source:
            merged = copy.copy(destination)
        else:
            merged = destination

        for key, value in source.items():
            if isinstance(value, dict):
                # get node or create one
                if key in merged:
                    # recursively merge
                    merged[key] = self._merge_job_dicts(value, merged[key])
                else:
                    merged[key] = value
            else:
                merged[key] = value

        return merged
