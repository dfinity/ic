import pprint
import sys
from typing import Dict
from typing import Iterator
from typing import List

from elasticsearch import Elasticsearch
from elasticsearch import exceptions


class EsException(Exception):
    pass


class Es:

    # This array represents a lexicographical order.
    # To scroll through ES pages, we need two factors:
    # 1. Timestamps, ascending (note that their order
    #    is a global invariant, so the point-in-time
    #    concept is not needed here).
    # 2. Unique IDs, descending (could be ascending,
    #    probably) -- TODO
    _SORTER = [
        {"@timestamp": {"order": "asc"}},
        # {"_id", {"order" : "desc"}}
    ]

    @staticmethod
    def _bookmark(last_hit) -> List[str]:
        # [last_hit[0], str(last_hit[1])]
        return [last_hit[0]]

    stat: Dict[str, Dict[str, int]]

    def __init__(self, es_url: str):
        self.es_url = es_url
        self.es = Elasticsearch(es_url)
        self.stat = {"raw_logs": dict()}

    @staticmethod
    def _precise_query(tag: str):
        return {"match": {"tags": {"query": tag, "operator": "and", "fuzziness": "0"}}}

    def find_indices(self, tag: str) -> List[str]:
        result = []
        for index in self.es.indices.get_alias(index="*"):
            body = {"query": Es._precise_query(tag)}
            try:
                response = self.es.count(index=index, body=body)
            except exceptions.TransportError as e:
                sys.stderr.write(
                    f"ERROR: ES did not respond to COUNT query "
                    f"for index {index}\n"
                    f"request body: {pprint.pformat(body)}\n"
                    f"exception:\n{str(e)}\n"
                )
                raise e

            size = int(response["count"])
            if size > 0:
                sys.stderr.write(f"Found index {str(index)} with {size} " f"documents tagged {tag}\n")
                result.append(index)

                # Save statistics:
                # total number of raw log messages sent to Elasticsearch
                assert tag not in self.stat["raw_logs"], "duplicate tag"
                self.stat["raw_logs"][tag] = size

        return result

    def stream(self, indices: List[str], tag: str, page_size=20) -> Iterator:

        query = Es._precise_query(tag)

        try:
            response = self.es.search(index=indices, size=page_size, sort=Es._SORTER, query=query)
        except exceptions.TransportError as error:
            sys.stderr.write(
                "\n"
                "ES query failed.\n"
                "If your Farm tests have started recently, try repeating "
                "this script in a few minutes.\n"
            )
            raise error

        docs = response["hits"]["hits"]

        if not docs:
            raise EsException(f"No ES documents were found for tag `{tag}` " f"in indices `{','.join(indices)}`")

        for doc in docs:
            yield doc

        last_hit = docs[-1]["sort"]

        while True:
            sys.stderr.write(".")
            sys.stderr.flush()

            bookmark = Es._bookmark(last_hit)

            response = self.es.search(
                index=indices, size=page_size, sort=Es._SORTER, query=query, search_after=bookmark
            )
            docs = response["hits"]["hits"]

            if not docs:
                sys.stderr.write("\n")
                sys.stderr.flush()
                break

            for doc in docs:
                yield doc

            last_hit = docs[-1]["sort"]
