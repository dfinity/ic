import sys

import gflags

FLAGS = gflags.FLAGS
gflags.DEFINE_boolean(
    "verifies_perf", False, "Specifies whether performance verification against target values is needed."
)
gflags.DEFINE_integer("median_latency_threshold", 3000, "Median latency threshold for query calls.")


class VerifyPerf:
    """Verifies performance on metrics."""

    def __init__(self, result: str = None):
        self.__result_file = result
        self.__failures = 0

    def __print(self, message: str):
        """Prints the message to file if output file is provided. Otherwise, print to console."""
        if self.__result_file is None or self.__result_file == "":
            print(message)
        else:
            with open(self.__result_file, "a") as results:
                results.write(message)

    def verify(self, metric: str, is_update: bool, actual: float, expected: float):
        """Check deviation is within threshold between actual and expected rate."""
        if not FLAGS.verifies_perf:
            return

        call_method = "Update" if is_update is True else "Query"

        if expected == 0 and actual != 0 or expected > 0 and actual > expected or expected < 0 and actual < expected:
            self.__print(f"❌{call_method} {metric} of value {actual} did not meet expectation {expected}, fail!\n")
            self.__failures += 1
        else:
            self.__print(f"✅{call_method} {metric} of value {actual} met expectation {expected}, success!\n")

    def is_success(self):
        """Checks whether there is any failure in performance verifications till current point."""
        if not FLAGS.verifies_perf:
            return True

        return self.__failures <= 0

    def conclude(self):
        """Concludes the performance verifications"""
        if not FLAGS.verifies_perf:
            return

        if self.__failures > 0:
            print(
                f"❌ Performance did not meet expectation. Check {self.__result_file} file for more detailed results. 😭😭😭"
            )
            sys.exit(1)

        print("✅ Performance verifications passed! 🎉🎉🎉")
        sys.exit(0)
