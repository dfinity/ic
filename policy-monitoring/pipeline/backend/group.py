from typing import Iterable
from typing import Optional

from pipeline.es_doc import ReplicaDoc
from pipeline.global_infra import GlobalInfra
from util.print import eprint


class Group:
    def __init__(
        self,
        gid: str,
        logs: Iterable = [],
        ci_job_id: Optional[int] = None,
        url: Optional[str] = None,
        global_infra: Optional[GlobalInfra] = None,
    ):
        self.logs = logs
        self.gid = gid
        self.ci_job_id = ci_job_id
        self.url = url
        self.global_infra = global_infra

    def __str__(self) -> str:
        """Logging-friendly representation"""
        optional_fields = []
        if self.ci_job_id:
            optional_fields.append(f"ci_job_id={self.ci_job_id}")
        if self.url:
            optional_fields.append(f"url={self.url}")
        return f"<Group gid={self.gid} {' '.join(optional_fields)}>"

    def infer_global_infra(self) -> None:
        eprint(f"Inferring global infra for {str(self)}...")
        orch_docs = [ReplicaDoc(doc.repr) for doc in self.logs if doc.is_replica()]
        self.global_infra = GlobalInfra.fromReplicaLogs(replica_docs=orch_docs)
        eprint(f"Inferring global infra for {str(self)} done.")
