from tests import global_infra_io
from tests import mfotl_sanity
from tests import monpoly_io


def run_all_tests():
    mfotl_sanity.run_test()
    monpoly_io.run_test()
    global_infra_io.run_test()


if __name__ == "__main__":
    run_all_tests()
