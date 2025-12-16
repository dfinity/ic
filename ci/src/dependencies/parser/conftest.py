import os


def pytest_sessionstart(session):
    # set the working dir to the dir of the script to allow accessing test_data with relative paths
    os.chdir(os.path.dirname(__file__))
