"""
Test the DFINITY GitLAB YAML validator.

Requires GITLAB_API_TOKEN env var points to a GitLab token with API access. You can create one here:
https://gitlab.com/-/profile/personal_access_tokens
"""
import json
import textwrap

import pytest
import yaml

from . import DfinityGitLabConfig
from . import utils


def test_ci_config_good():
    """Test the good path of the CI config validation."""
    cfg = textwrap.dedent(
        """\
        scenario-generic-nightly:
            stage: test
            tags:
                - cd
            needs: []
            rules:
                - if: '$CI_PIPELINE_SOURCE == "schedule" && $CD_ENV == $cd_target_env'
                - if: '$CI_PIPELINE_SOURCE == "web"'
                  when: manual
            resource_group: $TESTNET
            artifacts:
                when: always
                paths:
                - $CI_JOB_STAGE/$CI_JOB_NAME
            script:
            - nix run -f default.nix dfinity.prod.tests.scenario-tests --show-trace -c scenario-tests-generic
                "$TESTNET" 18000 100 1k "$CI_JOB_STAGE/$CI_JOB_NAME"
            - touch "/tmp/job_success_$CI_JOB_ID"
            timeout: 6 hours
            variables:
                cd_target_env: NIGHTLY
        """
    )
    gl = DfinityGitLabConfig()
    gl.ci_cfg_load(cfg)
    gl.ci_cfg_lint()


def test_ci_config_no_job():
    """Test the CI config validation with no job defined (invalid)."""
    cfg = textwrap.dedent(
        """\
        .cargo-master-prs:
            extends: .cargo-rules
            interruptible: true
            rules:
            - if: $CI_PIPELINE_SOURCE == "push"
            - if: $CI_PIPELINE_SOURCE == "web"
              when: manual
        .cargo-rules:
            rules:
            - if: $CI_PIPELINE_SOURCE == "push"
            - if: $CI_PIPELINE_SOURCE == "web"
              when: manual
            """
    )
    gl = DfinityGitLabConfig()
    with pytest.raises(ValueError):
        gl.ci_cfg_load(cfg)
        gl.ci_cfg_lint()


def test_ci_config_space_in_job_name():
    """Test the CI config validation with no job defined (invalid)."""
    cfg = textwrap.dedent(
        """\
        scenario generic nightly:
            stage: test
            script:
            - echo hello
            """
    )
    gl = DfinityGitLabConfig()
    with pytest.raises(ValueError):
        gl.ci_cfg_load(cfg)
        gl.ci_cfg_lint()


def test_ci_config_cfg_not_string():
    """Test the CI config validation without a string config (invalid)."""
    cfg = {"job_name": "job_data"}
    gl = DfinityGitLabConfig()
    with pytest.raises(ValueError):
        gl.ci_cfg_load(cfg)
        gl.ci_cfg_lint()


def test_simple_script():
    cfg = textwrap.dedent(
        """\
        before_script:
          - echo "Before script"
        after_script:
          - echo "After script"
        cargo-master-prs:
            script: "echo 'Hello'"
            stage: build
        """
    )
    ci_cfg_expected = yaml.load(
        textwrap.dedent(
            """\
            before_script:
            - echo "Before script"
            after_script:
            - echo "After script"
            cargo-master-prs:
                before_script:
                - echo "Before script"
                script: "echo 'Hello'"
                after_script:
                - echo "After script"
                stage: build
            """
        ),
        Loader=yaml.FullLoader,
    )
    gl = DfinityGitLabConfig()
    gl.ci_cfg_load(cfg)
    ci_cfg_json = json.dumps(gl.ci_cfg_expanded, indent=2, sort_keys=True)
    expected = json.dumps(ci_cfg_expected, indent=2, sort_keys=True)
    assert ci_cfg_json == expected
    gl.ci_cfg_lint()
    job_script = gl.ci_job_script("cargo-master-prs")
    assert "echo 'Hello'" in job_script
    assert 'echo "Before script"' in job_script
    assert 'echo "After script"' in job_script


def test_extends():
    cfg = textwrap.dedent(
        """\
        before_script:
          - echo "Before script"
        after_script:
          - echo "After script"
        cargo-master-prs:
            extends: .cargo-rules
            interruptible: true
            script:
            - echo Hello
            variables:
              OTHER_VAR: "var_value"
        .cargo-rules:
            rules:
            - if: $CI_PIPELINE_SOURCE == "push"
            - if: $CI_PIPELINE_SOURCE == "web"
              when: manual
            variables:
              SHELL_WRAPPER: "/usr/bin/time"
        """
    )
    ci_cfg_expected = yaml.load(
        textwrap.dedent(
            """\
            before_script:
            - echo "Before script"
            after_script:
            - echo "After script"
            cargo-master-prs:
                rules:
                - if: $CI_PIPELINE_SOURCE == "push"
                - if: $CI_PIPELINE_SOURCE == "web"
                  when: manual
                interruptible: true
                before_script:
                - echo "Before script"
                script:
                - echo Hello
                after_script:
                - echo "After script"
                variables:
                  OTHER_VAR: "var_value"
                  SHELL_WRAPPER: "/usr/bin/time"
            """
        ),
        Loader=yaml.FullLoader,
    )
    gl = DfinityGitLabConfig()
    gl.ci_cfg_load(cfg)
    ci_cfg_json = json.dumps(gl.ci_cfg_expanded, indent=2, sort_keys=True)
    expected = json.dumps(ci_cfg_expected, indent=2, sort_keys=True)
    assert ci_cfg_json == expected


def test_extends_complex():
    cfg = textwrap.dedent(
        """\
        before_script:
            - echo "Before script"
        after_script:
            - echo "After script"
        .cargo-docker:
            image:
                name: "registry.gitlab.com/dfinity-lab/core/docker/rs-builder-ubuntu:nix-2.3.10"
            tags:
                # Build on dfinity runners docker and ubuntu tags
                - dfinity
                - docker
                - ubuntu
            variables:
                GIT_DEPTH: 0  # Pull the complete repo initially
                GIT_STRATEGY: "fetch"  # And then pull only new commits
            script:
                - echo ".cargo-docker script command 1"
        .cargo-crate-test:
            extends: .cargo-docker
            rules:
                - if: '$CI_PIPELINE_SOURCE == "parent_pipeline"'
            stage: cargo-test
            needs: []
            artifacts:
                reports:
                junit: test_report.xml
            variables:
                RUST_BACKTRACE: 1
                CARGO_TEST_FLAGS_EXTRA: ""
                CARGO_TEST_TIMEOUT: 3600
            script:
                - echo ".cargo-crate-test script command 1"
                - |
                    echo ".cargo-crate-test script command 2 multiline"
        .cargo-build-docker:
            extends: .cargo-docker
            rules:
                - if: '$CI_PIPELINE_SOURCE == "parent_pipeline"'
            stage: cargo-build
        cargo-build-debug:
            extends: .cargo-build-docker
            variables:
                BUILD_COMMAND: "cargo build"
        cargo-build-release:
            extends: .cargo-build-docker
            artifacts:
                paths:
                - artifacts/nix-release/*.gz
            variables:
                BUILD_COMMAND: "cargo build --release"
                BUILD_COMMAND_POST: "${CI_PROJECT_DIR}/gitlab-ci/src/artifacts/collect_build_binaries.py"
        ic-consensus:
            extends: .cargo-crate-test
        ic-crypto:
            extends: .cargo-crate-test
            variables:
                CARGO_TEST_FLAGS_EXTRA: "--release"
        """
    )
    ci_cfg_expected = yaml.load(
        textwrap.dedent(
            """\
        before_script:
            - echo "Before script"
        after_script:
            - echo "After script"
        cargo-build-debug:
            rules:
                - if: '$CI_PIPELINE_SOURCE == "parent_pipeline"'
            stage: cargo-build
            image:
                name: "registry.gitlab.com/dfinity-lab/core/docker/rs-builder-ubuntu:nix-2.3.10"
            tags:
                # Build on dfinity runners docker and ubuntu tags
                - dfinity
                - docker
                - ubuntu
            variables:
                GIT_DEPTH: 0  # Pull the complete repo initially
                GIT_STRATEGY: "fetch"  # And then pull only new commits
                BUILD_COMMAND: "cargo build"
            before_script:
                - echo "Before script"
            after_script:
                - echo "After script"
            script:
                - echo ".cargo-docker script command 1"
        cargo-build-release:
            rules:
                - if: '$CI_PIPELINE_SOURCE == "parent_pipeline"'
            stage: cargo-build
            image:
                name: "registry.gitlab.com/dfinity-lab/core/docker/rs-builder-ubuntu:nix-2.3.10"
            tags:
                # Build on dfinity runners docker and ubuntu tags
                - dfinity
                - docker
                - ubuntu
            variables:
                GIT_DEPTH: 0  # Pull the complete repo initially
                GIT_STRATEGY: "fetch"  # And then pull only new commits
                BUILD_COMMAND: "cargo build --release"
                BUILD_COMMAND_POST: "${CI_PROJECT_DIR}/gitlab-ci/src/artifacts/collect_build_binaries.py"
            before_script:
                - echo "Before script"
            after_script:
                - echo "After script"
            script:
                - echo ".cargo-docker script command 1"
            artifacts:
                paths:
                - artifacts/nix-release/*.gz
        ic-consensus:
            rules:
                - if: '$CI_PIPELINE_SOURCE == "parent_pipeline"'
            stage: cargo-test
            needs: []
            artifacts:
                reports:
                junit: test_report.xml
            variables:
                CARGO_TEST_FLAGS_EXTRA: ""
                CARGO_TEST_TIMEOUT: 3600
                GIT_DEPTH: 0  # Pull the complete repo initially
                GIT_STRATEGY: "fetch"  # And then pull only new commits
                RUST_BACKTRACE: 1
            image:
                name: "registry.gitlab.com/dfinity-lab/core/docker/rs-builder-ubuntu:nix-2.3.10"
            tags:
                # Build on dfinity runners docker and ubuntu tags
                - dfinity
                - docker
                - ubuntu
            before_script:
                - echo "Before script"
            after_script:
                - echo "After script"
            script:
                - echo ".cargo-crate-test script command 1"
                - |
                    echo ".cargo-crate-test script command 2 multiline"
        ic-crypto:
            rules:
                - if: '$CI_PIPELINE_SOURCE == "parent_pipeline"'
            stage: cargo-test
            needs: []
            artifacts:
                reports:
                junit: test_report.xml
            variables:
                CARGO_TEST_FLAGS_EXTRA: "--release"
                CARGO_TEST_TIMEOUT: 3600
                GIT_DEPTH: 0  # Pull the complete repo initially
                GIT_STRATEGY: "fetch"  # And then pull only new commits
                RUST_BACKTRACE: 1
            image:
                name: "registry.gitlab.com/dfinity-lab/core/docker/rs-builder-ubuntu:nix-2.3.10"
            tags:
                # Build on dfinity runners docker and ubuntu tags
                - dfinity
                - docker
                - ubuntu
            before_script:
                - echo "Before script"
            after_script:
                - echo "After script"
            script:
                - echo ".cargo-crate-test script command 1"
                - |
                    echo ".cargo-crate-test script command 2 multiline"
        """
        ),
        Loader=yaml.FullLoader,
    )
    gl = DfinityGitLabConfig()
    gl.ci_cfg_load(cfg)
    ci_cfg_json = utils.yaml_dump_sorted_without_anchors(gl.ci_cfg_expanded)
    expected = utils.yaml_dump_sorted_without_anchors(ci_cfg_expected)
    assert ci_cfg_json == expected


if __name__ == "__main__":
    pytest.main([__file__])
