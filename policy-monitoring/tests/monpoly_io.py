import os
from os.path import isdir
from os.path import join
from posixpath import abspath
from posixpath import dirname

from monpoly.monpoly import Monpoly
from util import docker

from .common import run_tests

pwd = dirname(abspath(__file__))
tests_dir = join(pwd, "io_test_resources")
tests = [t for t in os.listdir(tests_dir) if isdir(join(tests_dir, t))]

# Test that MonPoly can be run on this system via Docker
if not docker.is_inside_docker():
    Monpoly.install_docker_image()

# Run all tests
run_tests(tests_dir, tests)
