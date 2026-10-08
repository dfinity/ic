import os
import unittest
from pathlib import Path

from toolchains.sysimage.dockerfile import Copy, DockerfileError, Run, plan


def runfile(path: str) -> Path:
    return Path(os.environ["TEST_SRCDIR"]) / os.environ.get("TEST_WORKSPACE", "_main") / path


class PlanTest(unittest.TestCase):
    def test_multi_stage_chain(self):
        text = """
# comment
ARG BASE_IMAGE=
ARG BUILD_TYPE=
FROM $BASE_IMAGE as output_prod
USER root:root
COPY etc /etc
RUN echo prod
FROM output_prod as output_dev
ARG ROOT_PASSWORD=
RUN echo dev
FROM output_${BUILD_TYPE}
USER root:root
"""
        dev = plan(text, {"BASE_IMAGE": "img@sha256:1", "BUILD_TYPE": "dev", "ROOT_PASSWORD": "pw"})
        self.assertEqual(dev.base_image, "img@sha256:1")
        self.assertEqual(
            dev.steps,
            [
                Copy(sources=["etc"], destination="/etc"),
                Run(command="echo prod"),
                Run(command="echo dev", args={"ROOT_PASSWORD": "pw"}),
            ],
        )
        prod = plan(text, {"BASE_IMAGE": "img@sha256:1", "BUILD_TYPE": "prod"})
        self.assertEqual(prod.steps, [Copy(sources=["etc"], destination="/etc"), Run(command="echo prod")])

    def test_line_continuation_is_removed_like_docker(self):
        steps = plan("FROM base\nRUN chmod 0755 /a \\\n    /b && \\\n    true\n", {}).steps
        self.assertEqual(steps, [Run(command="chmod 0755 /a     /b &&     true")])

    def test_comment_lines_inside_continuation_are_dropped(self):
        steps = plan("FROM base\nRUN a \\\n# note\n  b\n", {}).steps
        self.assertEqual(steps, [Run(command="a   b")])

    def test_copy_chmod(self):
        steps = plan("FROM base\nCOPY --chmod=644 etc/hosts /etc/hosts\n", {}).steps
        self.assertEqual(steps, [Copy(sources=["etc/hosts"], destination="/etc/hosts", chmod="644")])

    def test_arg_default_and_override(self):
        steps = plan("FROM base\nARG A=1\nARG B\nRUN x\n", {"B": "2"}).steps
        self.assertEqual(steps, [Run(command="x", args={"A": "1", "B": "2"})])

    def test_stage_arg_without_default_inherits_the_global_default(self):
        self.assertEqual(
            plan("ARG V=glob\nFROM base\nARG V\nRUN x\n", {}).steps, [Run(command="x", args={"V": "glob"})]
        )
        self.assertEqual(
            plan("ARG V=glob\nFROM base\nARG V\nRUN x\n", {"V": "arg"}).steps, [Run(command="x", args={"V": "arg"})]
        )

    def test_empty_lines_in_a_continuation_are_skipped(self):
        self.assertEqual(plan("FROM base\nRUN a \\\n\n  b\n", {}).steps, [Run(command="a   b")])

    def test_stage_args_are_inherited_by_stages_based_on_the_stage(self):
        text = "FROM base AS one\nARG A=1\nRUN x\nFROM one\nRUN y\n"
        self.assertEqual(plan(text, {}).steps, [Run(command="x", args={"A": "1"}), Run(command="y", args={"A": "1"})])

    def test_stage_args_are_not_visible_in_unrelated_stages(self):
        text = "FROM base AS one\nARG A=1\nRUN x\nFROM base AS two\nRUN y\n"
        self.assertEqual(plan(text, {}).steps, [Run(command="y")])

    def test_unsupported_syntax_is_rejected(self):
        for text in [
            "FROM base\nENV A=1\n",
            "FROM base\nWORKDIR /x\n",
            "FROM base\nUSER nobody\n",
            'FROM base\nRUN ["echo", "x"]\n',
            "FROM base\nRUN --mount=type=cache,target=/x echo\n",
            "FROM base\nCOPY --chown=1:1 a /a\n",
            "FROM base\nCOPY --from=other /a /a\n",
            "FROM base\nCOPY *.txt /a/\n",
            "FROM base\nCOPY ../a /a\n",
            "FROM base\nCOPY a /x/${B:-default}/\n",
            "FROM base\nCOPY a /x/\\$HOME\n",
            "# escape=`\nFROM base\n",
            "# syntax=docker/dockerfile:1\nFROM base\n",
            'FROM base\nARG A="x y"\n',
            "FROM --platform=linux/amd64 base\n",
            "FROM base\nADD a /a\n",
            "RUN x\n",
            "",
        ]:
            with self.subTest(text=text), self.assertRaises(DockerfileError):
                plan(text, {})

    def test_icos_dockerfiles(self):
        for path, build_args in [
            ("ic-os/guestos/context/Dockerfile", {"BUILD_TYPE": "dev", "ROOT_PASSWORD": "root"}),
            ("ic-os/guestos/context/Dockerfile", {"BUILD_TYPE": "prod"}),
            ("ic-os/hostos/context/Dockerfile", {"BUILD_TYPE": "dev", "ROOT_PASSWORD": "root"}),
            ("ic-os/hostos/context/Dockerfile", {"BUILD_TYPE": "prod"}),
            ("ic-os/setupos/context/Dockerfile", {"BUILD_TYPE": "prod"}),
            ("ic-os/bootloader/context/Dockerfile", {}),
        ]:
            with self.subTest(path=path, build_args=build_args):
                result = plan(runfile(path).read_text(), {"BASE_IMAGE": "base@sha256:0"} | build_args)
                self.assertEqual(result.base_image, "base@sha256:0")
                self.assertTrue(any(isinstance(step, Run) for step in result.steps))
                dev_only = [s for s in result.steps if isinstance(s, Run) and "ROOT_PASSWORD" in s.args]
                if build_args.get("BUILD_TYPE") == "prod":
                    self.assertEqual(dev_only, [])


if __name__ == "__main__":
    unittest.main()
