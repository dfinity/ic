import datetime
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class GHSubDependency:
    package_url: str
    dependencies: Optional[List[str]] = None

    def to_json(self):
        res = {"package_url": self.package_url}
        if self.dependencies is not None and len(self.dependencies) > 0:
            res["dependencies"] = self.dependencies
        return res


@dataclass
class GHSubManifest:
    name: str
    source_location: str
    resolved: Optional[List[GHSubDependency]] = None

    def to_json(self):
        res = {"name": self.name, "file": {"source_location": self.source_location}, "resolved": {}}
        for r in self.resolved:
            res["resolved"][r.package_url] = r.to_json()
        return res


@dataclass
class GHSubJob:
    job_id: str
    correlator: str
    html_url: Optional[str] = None

    def to_json(self):
        res = {"id": self.job_id, "correlator": self.correlator}
        if self.html_url is not None:
            res["html_url"] = self.html_url
        return res


@dataclass
class GHSubDetector:
    name: str
    version: str
    url: str

    def to_json(self):
        return {"name": self.name, "version": self.version, "url": self.url}


@dataclass
class GHSubRequest:
    version: int
    job: GHSubJob
    sha: str
    ref: str
    detector: GHSubDetector
    manifests: List[GHSubManifest]
    scanned: str = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_json(self):
        res = {
            "version": self.version,
            "job": self.job.to_json(),
            "sha": self.sha,
            "ref": self.ref,
            "detector": self.detector.to_json(),
            "manifests": {},
            "scanned": self.scanned,
        }
        for m in self.manifests:
            res["manifests"][m.name] = m.to_json()
        return res
