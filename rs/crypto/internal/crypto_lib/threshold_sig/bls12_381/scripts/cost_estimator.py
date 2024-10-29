#!/usr/bin/python
# coding=utf8

"""
Cost Estimator for NIDKG operations.

This script helps estimate the cost of various NIDKG operations,
allowing the user to easily examine how changes to system parameters
might affect the performance.

For example, the NIDKG chunking proof uses a parameter `l` which can
be modified; if you change it from 32 to 64, this affects not just the
size and cost of the chunking proof, but also the worst case runtime
for NIDKG dealing decryption (in the malicious case).

The script is a repl accepting a simple command language. The prompt
starts with "> " and the text the user enters follows.

The main commands are `eval` and `eval_all` to evaluate expressions.
Use `set` to modify an existing variable or to create a new one.

You can check which expressions exist using `keys`. This command
optionally takes a prefix, so for example `keys bsgs` shows all
expressions that start with "bsgs"

If Python finds a working readline library, then tab completion is
available.

Use "quit" or enter an EOF (Ctrl-D) to exit.

Welcome to NIDKG cost estimator
> set subnet_size = 40
> eval fs_decryption_worst_cost
fs_decryption_worst_cost = 21.8 minutes
> set bsgs_table_mult = 30
> eval fs_decryption_worst_cost bsgs_table_bytes
fs_decryption_worst_cost = 16.2 minutes
bsgs_table_bytes = 1494.67 MiB
> keys
# prints all of the keys
> eval_all
# evaluates all saved expressions
> quit
(exits)

"""

import ast
import cmd
import math
import operator as op


def cost(group, op, n=1):
    assert n >= 1

    # all costs are in microseconds
    costs = {
        "g1": {
            "mul": 276,
            "mul2": 360,
            "hash": 110,
            "serialize": 29,
            "deserialize": 113,
        },
        "g2": {
            "mul": 835,
            "serialize": 34,
            "deserialize": 410,
        },
        "gt": {"pair4": 2253, "search16": 300, "add": 5},
    }

    muln_costs = {
        "g1": {
            2: 268,
            4: 534,
            8: 1068,
            12: 1622,
            16: 2047,
            24: 2554,
            32: 3048,
            48: 3988,
            64: 4808,
            96: 6390,
            128: 7958,
            256: 14364,
        },
        "g2": {
            2: 845,
            4: 1711,
            8: 3485,
            12: 5100,
            16: 6903,
            24: 8602,
            32: 10382,
            48: 13513,
            64: 16317,
            96: 21738,
            128: 27324,
            256: 48344,
        },
    }

    if op == "muln_sparse":
        return int(0.1 * cost(group, "muln", n))

    if op == "muln":
        if group in muln_costs:
            avail = muln_costs[group].keys()

            if n in avail:
                return muln_costs[group][n]
            closest = min(avail, key=lambda x: abs(x - n))

            # scale linearly vs closest available result
            return int(n * (muln_costs[group][closest] / closest))
        else:
            # just assume naive mul
            return cost(group, "mul", n)

    return n * costs[group][op]


class Time(object):
    def __init__(self, n):
        self.val = n

    def __add__(self, o):
        return Time(self.val + o.val)

    def __mul__(self, o):
        assert isinstance(o, int)
        return Time(self.val * o)

    def __rmul__(self, o):
        assert isinstance(o, int)
        return Time(self.val * o)

    def __str__(self):
        us = self.val

        if us < 1000:
            return "%d μs" % (us)

        ms = us / 1000
        if ms < 1000:
            return "%.02f ms" % (ms)

        s = ms / 1000

        if s < 60:
            return "%.02f sec" % (s)

        minutes = s / 60

        if minutes < 60:
            return "%.01f minutes" % (minutes)

        hours = minutes / 60
        return "%.02f hours" % (hours)


class Bytes(object):
    def __init__(self, n):
        if isinstance(n, int):
            self.val = n
        else:
            assert isinstance(n, Bytes)
            self.val = n.val

    def __add__(self, o):
        return Bytes(self.val + o.val)

    def __mul__(self, o):
        assert isinstance(o, int)
        return Bytes(self.val * o)

    def __rmul__(self, o):
        assert isinstance(o, int)
        return Bytes(self.val * o)

    def __str__(self):
        bytes = self.val

        if bytes >= 1024 * 1024:
            return "%.02f MiB" % (bytes / (1024 * 1024))

        return "%d bytes" % (bytes)


class NidkgCosts(object):
    def __init__(self):
        self.params = {}

    def set_var(self, nm, expr):
        self.params[nm] = expr

    def parse_vars(self, str):
        for line in str.split("\n"):
            if line == "" or line.startswith("#"):
                continue

            try:
                (k, v) = line.split(" = ")
                self.set_var(k, v)
            except ValueError:
                print("Failed to parse '%s' as key = val" % (line))

    def expr(self, nm):
        return self.params[nm]

    def match_prefix(self, prefix):
        matches = []

        for key in self.params:
            if key.startswith(prefix):
                matches.append(key)

        return matches

    def eval(self, nm):
        expr = self.params[nm]
        return self._eval(ast.parse(expr, mode="eval").body)

    def eval_all(self):
        results = []
        for nm in self.params:
            expr = self.params[nm]
            val = self._eval(ast.parse(expr, mode="eval").body)
            results.append((nm, val))
        return results

    def _eval(self, node):
        operators = {
            ast.Add: op.add,
            ast.Sub: op.sub,
            ast.Mult: op.mul,
            ast.FloorDiv: op.floordiv,
            ast.Div: op.truediv,
            ast.Pow: op.pow,
            ast.USub: op.neg,
        }

        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.BinOp):  # <left> <operator> <right>
            return operators[type(node.op)](self._eval(node.left), self._eval(node.right))
        elif isinstance(node, ast.Name):
            val = self.eval(node.id)
            if node.id.endswith("_bytes"):
                return Bytes(val)
            else:
                return val
        elif isinstance(node, ast.Call):
            if node.func.id == "pow2":
                assert len(node.args) == 1
                val = self._eval(node.args[0])
                return (1 << val) - 1
            if node.func.id == "ceil":
                assert len(node.args) == 1
                val = self._eval(node.args[0])
                return math.ceil(val)
            if node.func.id == "sqrt":
                assert len(node.args) == 1
                val = self._eval(node.args[0])
                return math.ceil(math.sqrt(val))
            elif node.func.id == "cost":
                assert len(node.args) == 2 or len(node.args) == 3
                group = node.args[0].id
                oper = node.args[1].id
                n = 1  # default

                if len(node.args) == 3:
                    n = self._eval(node.args[2])

                return Time(cost(group, oper, n))
            else:
                raise Exception("Unknown func %s" % (node.func.id))
        else:
            raise Exception("Bad expression")


nidkg_expr = """
security_level = 256
g1_bytes = 48
g2_bytes = 96
gt_bytes = 576
gt_hash_bytes = 28
gt_hash_prefix_bytes = 5
scalar_bytes = 32

subnet_size = 28
receivers = subnet_size
dealers = threshold + 1

faults_tolerated = (subnet_size - 1) // 3

max_corrupt_dealers = faults_tolerated

threshold = (2 * receivers + 1) // 3

chunk_size = 16
chunking_rep = 32

challenge_bits = ceil(security_level / chunking_rep)

number_of_chunks = ceil(security_level / chunk_size)

# chunking proof
chunking_s = receivers * number_of_chunks * pow2(chunk_size) * pow2(challenge_bits)
chunking_z = 2 * chunking_s * chunking_rep

chunking_proof_bytes = g1_bytes*(2*chunking_rep + 3 + receivers) + scalar_bytes*(1 + chunking_rep + receivers)

chunking_proof_gen_cost = cost(g1,hash) + cost(g1,mul,chunking_rep) + cost(g1,mul,receivers+1) + cost(g1,muln,receivers + 1) + cost(g1,mul2,chunking_rep)

chunking_proof_verify_cost = cost(g1,mul,receivers+1) + receivers * cost(g1,muln,number_of_chunks) + chunking_rep*cost(g1,muln_sparse,receivers*number_of_chunks) + 2*cost(g1,muln,chunking_rep) + cost(g1,muln,receivers)

chunking_proof_number_of_g1 = (2*chunking_rep + 3 + receivers)

chunking_proof_serialize_cost = chunking_proof_number_of_g1 * cost(g1,serialize)
chunking_proof_deserialize_cost = chunking_proof_number_of_g1 * cost(g1,deserialize)

# sharing proof
sharing_proof_bytes = g1_bytes*2 + g2_bytes + scalar_bytes*2

sharing_proof_gen_cost = cost(g1,mul) + cost(g2,mul) + cost(g1,muln,receivers) + cost(g1,mul2)

sharing_proof_verify_cost = cost(g1,mul)*2 + cost(g2,muln,threshold) + 2*cost(g2,mul) + cost(g1,muln,receivers) + cost(g1,mul) + cost(g1,muln,receivers) + cost(g1,mul2)

public_coeff_bytes = threshold*g2_bytes

nidkg_ciphertext_bytes = number_of_chunks * (2*g1_bytes + g2_bytes) + receivers * number_of_chunks * g1_bytes

# this is size of a non-resharing transcript
nidkg_transcript_bytes = (max_corrupt_dealers + 1) * nidkg_ciphertext_bytes + public_coeff_bytes

nidkg_dealing_bytes = public_coeff_bytes + nidkg_ciphertext_bytes + chunking_proof_bytes + sharing_proof_bytes

# see https://ntietz.com/blog/rust-hashmap-overhead/
hashset_overhead = 1.73

bsgs_table_mult = 20
bsgs_index_bytes = 8
bsgs_range = 2*chunking_z - 1
bsgs_table_elements = bsgs_table_mult * sqrt(bsgs_range)
bsgs_full_gt_table_bytes = bsgs_table_elements * (gt_hash_bytes + bsgs_index_bytes)
bsgs_filter_bytes = ceil(bsgs_table_elements * hashset_overhead) * gt_hash_prefix_bytes

bsgs_table_bytes = bsgs_full_gt_table_bytes + bsgs_filter_bytes

bsgs_setup_cost = bsgs_table_elements * cost(gt,add)
bsgs_online_ops = ceil(bsgs_range / bsgs_table_elements)
bsgs_online_cost = bsgs_online_ops * cost(gt,add)

cheating_dealer_scale_range = pow2(challenge_bits)

cheating_dealer_setup_cost = bsgs_setup_cost

cheating_dealer_search_cost = cheating_dealer_scale_range*bsgs_online_cost

fs_decryption_usual_cost = number_of_chunks * (cost(gt, pair4) + cost(gt, search16))
fs_decryption_worst_cost = fs_decryption_usual_cost + cheating_dealer_setup_cost + number_of_chunks*cheating_dealer_search_cost
"""


class Repl(cmd.Cmd, object):
    intro = "Welcome to NIDKG cost estimator"
    prompt = "> "

    def __init__(self, nidkg_expr):
        super(Repl, self).__init__()
        self.rules = NidkgCosts()
        if nidkg_expr is not None:
            self.rules.parse_vars(nidkg_expr)

    def do_eval(self, arg):
        """Evaluate an expression"""
        try:
            for v in arg.split(" "):
                for f in self.rules.match_prefix(v):
                    print("%s = %s" % (f, self.rules.eval(f)))
        except KeyError as e:
            print("Variable not found: ", e)

    def complete_eval(self, text, line, begidx, endidx):
        return sorted(self.rules.match_prefix(text))

    def do_eval_all(self, arg):
        """Evaluate all stored expressions"""
        for key, val in self.rules.eval_all():
            print("%s = %s" % (key, val))

    def do_set(self, arg):
        """Set a variable"""
        self.rules.parse_vars(arg)

    def complete_set(self, text, line, begidx, endidx):
        return sorted(self.rules.match_prefix(text))

    def do_keys(self, arg):
        """List stored expressions (with optional prefix matching)"""
        for v in arg.split(" "):
            for f in self.rules.match_prefix(v):
                print("%s = %s" % (f, self.rules.expr(f)))

    def complete_keys(self, text, line, begidx, endidx):
        return sorted(self.rules.match_prefix(text))

    def do_quit(self, arg):
        """Exit the script"""
        print("\nGoodbye")
        return True

    def do_EOF(self, arg):
        print("\nGoodbye")
        return True


if __name__ == "__main__":
    Repl(nidkg_expr).cmdloop()
