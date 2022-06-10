import re
import subprocess
from typing import Dict
from typing import Set
from typing import Tuple

from monpoly.monpoly import Monpoly
from util.print import eprint


class ReproManager:
    def __init__(self, repros: Dict[str, Dict[str, Set[Tuple[str, ...]]]], stat: Dict[str, Dict]):
        """
        Create a new [ReproManager] object that can reproduce policy violations
        in non-interactive mode.

        [repros] maps group names to formula to set of repro cmds
        """
        self.repros = repros
        self.stat = stat

    @staticmethod
    def parse_tuple(text: str) -> Tuple[str, ...]:
        """Parse Monpoly violation tuple. Take double quotes into account."""
        quoted = False
        text = text.strip("()")
        if text == "":
            return ()
        res = []
        word = ""
        for char in text:
            if char == '"':
                quoted = not quoted
            elif not quoted and char == ",":
                res.append(word)
                word = ""
            else:
                word += char

        res.append(word)
        return tuple(res)

    @staticmethod
    def _count_violations(text: str) -> int:
        res = 0
        quoted = False
        opened = 0
        text = re.sub(r"\(time point \d+\)", "", text)
        for i, char in enumerate(text):
            if char == '"':
                quoted = not quoted
            elif not quoted and char == "(":
                res += 1
                opened += 1
            elif not quoted and char == ")":
                opened -= 1
                assert opened >= 0, f"invalid closing parenthesis at position {i}"

        assert opened == 0, f"{opened} too many opening parentheses"
        return res

    def reproduce_all_violations(self) -> None:
        """
        Run instances of policy violations once again in non-interactive mode.

        This enables counting the precise number of violations in each case.

        In the future, this could also help making user feedback more precise.
        """
        eprint("Running all repros ...")

        # pp = pprint.PrettyPrinter(indent=2)
        for group_name in self.repros:
            if group_name not in self.stat:
                self.stat[group_name] = dict()
            self.stat[group_name]["violations"] = dict()
            for formula in self.repros[group_name]:
                self.stat[group_name]["violations"][formula] = list()
                # repros: Set[ Tuple[str] ]
                repros = self.repros[group_name][formula]
                for repro_cmd in repros:
                    eprint(f" processing violation of policy {formula} @ group {group_name} ...", end="")

                    # Unquote all arguments since Popen adds its own quotes
                    repro_cmd_unquoted = tuple([arg.strip('"') for arg in repro_cmd])
                    # pp.pprint(repro_cmd_unquoted)
                    p = subprocess.run(repro_cmd_unquoted, capture_output=True)
                    self.stat[group_name]["violations"][formula].append(
                        {
                            "violations_count": self._count_violations(Monpoly.decode(p.stdout)),
                            "stderr_line_count": len(Monpoly.decode(p.stderr).split("\n")) - 1,
                            "repro_cmd": " ".join(repro_cmd),
                        }
                    )

                    eprint(" done.")

        eprint("All repros have terminated.")
