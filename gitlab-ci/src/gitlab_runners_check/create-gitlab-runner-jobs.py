#!/usr/bin/env python3
import os

import git
from gitlab import Gitlab
from jinja2 import Template

""" Generate a gitlab child pipeline dynamically in order to run a test on all idx runners"""


def main():
    git_repo = git.Repo(".", search_parent_directories=True)
    git_root = git_repo.git.rev_parse("--show-toplevel")

    location = os.path.join(git_root, "gitlab-ci/src/gitlab_runners_check/runners2.j2")
    template_file = open(location)
    job_template = template_file.read()
    template_file.close()

    if not os.getenv("GITLAB_TOKEN"):
        print("GITLAB_TOKEN env var not set")
        os.exit(1)
    token = os.getenv("GITLAB_TOKEN")

    gl = Gitlab("https://gitlab.com", private_token=token, per_page=100)

    # Gather all our runners into a nice list
    dfinity_runners = []
    for page in gl.runners.list(per_page=100, as_list=False, retry_transient_errors=True, scope="active"):
        dfinity_runners.append(page)

    idx_runners_list = []

    for runner in dfinity_runners:
        myrunner = gl.runners.get(runner.id)
        tag_list = myrunner.tag_list

        # Do not include a non-idx gitlab runner
        if "dfinity" in tag_list:
            idx_runners_list.append({"id": runner.id, "description": runner.description, "tags": tag_list})

    # Render the template
    dynamic_template = Template(job_template)
    x = dynamic_template.render(items=idx_runners_list)

    # Write the templated yml to our file for use as an artifact
    runners_file = open("runners.yml", "w")
    runners_file.write(x)
    runners_file.close()


if __name__ == "__main__":
    main()
