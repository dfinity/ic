# type: ignore
# Note: mypy does not see top-level attributes of the yaml module
from datetime import timedelta
from ipaddress import IPv6Address
from ipaddress import IPv6Network

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import Node
from yaml.nodes import ScalarNode
from yaml.nodes import SequenceNode


def cast_scalar(node: Node) -> ScalarNode:
    if isinstance(node, ScalarNode):
        return node
    else:
        raise ConstructorError("expected scalar node")


def cast_seq(node: Node) -> SequenceNode:
    if isinstance(node, SequenceNode):
        return node
    else:
        raise ConstructorError("expected sequence node")


yaml.add_representer(IPv6Network, lambda dumper, data: dumper.represent_scalar("!IPv6Network", str(data)))
yaml.add_constructor("!IPv6Network", lambda loader, node: IPv6Network(loader.construct_scalar(cast_scalar(node))))


yaml.add_representer(IPv6Address, lambda dumper, data: dumper.represent_scalar("!IPv6Address", str(data)))
yaml.add_constructor("!IPv6Address", lambda loader, node: IPv6Address(loader.construct_scalar(cast_scalar(node))))


yaml.add_representer(set, lambda dumper, data: dumper.represent_sequence("!set", list(data)))
yaml.add_constructor("!set", lambda loader, node: set(loader.construct_sequence(cast_seq(node))))


def timedelta_constructor(loader, node):
    value = loader.construct_scalar(cast_scalar(node))
    left, right = value.split(" ")
    if len(left) < 2 or len(right) < 3:
        raise ConstructorError(f"cannot parse value `{str(value)}` as timedelta")
    if left[-1] != "s":
        raise ConstructorError("first word in timedelta value must end with 's'")
    if right[-1] != "s":
        raise ConstructorError("last word in timedelta value must end with 'us'")
    sec, us = left[:-1], right[:-2]
    timedelta(seconds=sec, microseconds=us)


yaml.add_representer(
    timedelta,
    lambda dumper, data: dumper.represent_scalar("!timedelta", "%ds %dus" % (data.seconds, data.microseconds)),
)
yaml.add_constructor("!timedelta", timedelta_constructor)
