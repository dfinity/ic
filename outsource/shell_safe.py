import base64
import json
from typing import List
from typing import Union

Command = Union[str, List[str]]


def encode(obj: Command) -> str:
    """
    Encode a string in a shell-safe way.

    The resulting string is a representation of a python value that is:
    * json encoded, then
    * utf-8 encoded, then
    * base64 encoded.
    """
    # here we encode the command to a shell-safe value:
    # [ "echo", "hello" ] # python ->
    # '[ "echo", "hello" ]' # JSON encoded ->
    # b'[ "echo", "hello" ]' # JSON encoded, utf-8 encoded bytes ->
    # b'WyJlY2hvIiwgImhlbGxvIl0=' # base64 encoded bytes ->
    # 'WyJlY2hvIiwgImhlbGxvIl0=' # ascii representation of the encoded bytes
    safe = base64.b64encode(json.dumps(obj).encode("utf-8"))

    return safe.decode("ascii")


def decode(s: str) -> Command:
    """
    Decode a string that was encoded in a shell-safe way.

    The string is a representation of a python value that was:
    * json encoded, then
    * utf-8 encoded, then
    * base64 encoded.
    """
    return json.loads(base64.b64decode(s.encode("ascii")))
