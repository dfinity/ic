"""Pre-commit dependency validation and reporting job."""
import logging
import sys

import inventory


RED = "\033[0;31m"
RESET = "\033[0m"
logging.basicConfig(format="%(asctime)s %(levelname)-8s %(message)s", level=logging.INFO)


def main():
    """Run the pre-commit checks."""
    inventories = {
        "Cargo": inventory.Inventory(inventory.Cargo()),
    }
    errors = {}

    for name, inv in inventories.items():
        logging.info("Validating %s inventory", name)
        result = inv.validate()
        if result:
            errors[name] = result
        logging.info("Validating %s finished", name)

    if not errors:
        return

    has_fatal = False
    print(RED)
    for inv, errs in errors.items():
        for e in errs:
            print(inv, ": ", e.message, sep="")
            if e.is_fatal:
                has_fatal = True
    print(RESET)
    if has_fatal:
        sys.exit(1)


if __name__ == "__main__":
    main()
