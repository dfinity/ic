from __future__ import annotations

import json
import os
import re
import socket
from dataclasses import dataclass, field, fields
from http.server import BaseHTTPRequestHandler as BaseHandler
from http.server import HTTPServer
from typing import IO
from uuid import uuid4

STATUS_OK = 200
STATUS_NOT_FOUND = 404

CONTENT_TYPE_TEXT_PLAIN = "text/plain"
CONTENT_TYPE_JSON = "application/json"

API_CONTAINER_ZONE = {
    "account": {
        "id": "023e105f4ecef8ad9ca31a8372d0c353",
        "name": "Account",
    },
    "created_on": "2014-01-01T05:20:00.12345Z",
    "development_mode": 7200,
    "meta": {
        "custom_certificate_quota": 0,
        "page_rule_quota": 0,
        "phishing_detected": False,
        "multiple_railguns_allowed": False,
    },
    "modified_on": "2014-01-01T05:20:00.12345Z",
    "name_servers": [],
    "owner": {
        "type": "organization",
        "id": "023e105f4ecef8ad9ca31a8372d0c353",
        "name": "Example Organization",
    },
    "paused": False,
    "permissions": [],
    "status": "active",
    "type": "full",
}

API_CONTAINER_DNS_RECORD = {
    "meta": {"auto_added": False},
    "locked": False,
    "modified_on": "2014-01-01T05:20:00.12345Z",
    "created_on": "2014-01-01T05:20:00.12345Z",
    "proxiable": False,
    "proxied": False,
}


def uuid():
    return f"{uuid4()}".replace("-", "")


def wrap(*wrappers):
    def apply(fn):
        for wrapper in wrappers:
            fn = wrapper(fn)
        return fn

    return apply


@dataclass
class Container:
    name: str
    socket: str = field(default="/var/run/docker.sock", compare=False)

    def restart(self):
        data = f"POST /containers/{self.name}/restart HTTP/1.0\r\n".encode()

        # Connect to the Unix domain socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket)

        # Send the data
        sock.sendall(data + b"\n")

        # Close the socket
        sock.close()


def with_restart(container: Container):
    def apply(fn):
        def run(*args, **kwargs):
            try:
                result = fn(*args, **kwargs)
            except Exception as e:
                raise e
            finally:
                container.restart()
            return result

        return run

    return apply


@dataclass
class CNAME:
    id: str = field(default_factory=lambda: f"{uuid()}", init=False, compare=False)
    name: str
    canonical_name: str

    def content(self):
        return self.canonical_name

    def update(self, other):
        if not isinstance(other, type(self)):
            raise ValueError("invalid type")

        self.name = other.name
        self.canonical_name = other.canonical_name


@dataclass
class TXT:
    id: str = field(default_factory=lambda: f"{uuid()}", init=False, compare=False)
    name: str
    text: str

    def content(self):
        return self.text

    def update(self, other):
        if not isinstance(other, type(self)):
            raise ValueError("invalid type")

        self.name = other.name
        self.text = other.text


@dataclass
class Zone:
    id: str = field(default_factory=lambda: f"{uuid()}", init=False, compare=False)
    name: str
    records: list[CNAME | TXT] = field(default_factory=lambda: [], init=False)

    def get(self, record_id):
        for record in self.records:
            if record.id == record_id:
                return record

        return None

    def insert(self, record):
        for r in self.records:
            if r == record:
                raise ValueError(f"record is a duplicate of {r.id}")

        self.records.append(record)

    def update(self, record_id, record):
        r = self.get(record_id)
        if not r:
            raise ValueError(f"record {r.id} not found")

        r.update(record)

    def delete(self, record_id):
        self.records = [r for r in self.records if r.id != record_id]


@dataclass
class Corefile:
    zones: list[Zone]

    def write(self, w: IO):
        for zone in self.zones:
            # Header
            w.write(
                "\n".join(
                    [
                        f"{zone.name} " + "{",
                        f"    file /zones/{zone.name}.zone",
                        "    log",
                        "    errors",
                        "}\n",
                    ]
                )
            )


@dataclass
class MasterFile:
    zone: Zone

    def write(self, w: IO):
        # Header
        header = [
            "$TTL 1",
            f"$ORIGIN {self.zone.name}.",
            f"@    IN    SOA   ns1.example.com. {self.zone.name}. (",
            "      2023071301  ; Serial number",
            "      3600        ; Refresh",
            "      1800        ; Retry",
            "      604800      ; Expire",
            "      1 )         ; Minimum TTL",
            "",
        ]

        # CNAME
        cname = list()
        for r in self.zone.records:
            if isinstance(r, CNAME):
                # remove the origin
                record_name = r.name.replace(self.zone.name, "").rstrip(".")
                if len(record_name) == 0:
                    record_name = "@"
                cname.append(f"{record_name} IN CNAME {r.canonical_name}.")

        # TXT
        txt = list()
        for r in self.zone.records:
            if isinstance(r, TXT):
                # remove the origin
                record_name = r.name.replace(self.zone.name, "").rstrip(".")
                if len(record_name) == 0:
                    record_name = "@"
                cname.append(f'{record_name} IN TXT "{r.text}"')

        w.write("\n".join(header + cname + txt))


def with_persist(corefile_dir: str, zone_dir: str, zones: list[Zone]):
    def persist_corefile(zones: list[Zone]):
        file_path = os.path.join(corefile_dir, "Corefile")

        with open(file_path, "w") as file:
            cf = Corefile(zones)
            cf.write(file)

    def persist_zonefile(zone: Zone):
        file_path = os.path.join(zone_dir, f"{zone.name}.zone")

        with open(file_path, "w") as file:
            mf = MasterFile(zone)
            mf.write(file)

    def apply(fn):
        def run(*args, **kwargs):
            try:
                result = fn(*args, **kwargs)
            except Exception as e:
                raise e
            finally:
                persist_corefile(zones)
                for zone in zones:
                    persist_zonefile(zone)
            return result

        return run

    return apply


def encode_result(result):
    return json.dumps(
        {
            "errors": [],
            "messages": [],
            "success": True,
            "result_info": {
                "count": 1,
                "page": 1,
                "per_page": 20,
                "total_count": 2000,
            },
            "result": result,
        }
    ).encode("utf-8")


class Handler(BaseHandler):
    def __init__(
        self,
        *args,
        corefile_dir: str,
        zones_dir: str,
        zones: list[Zone],
        container: Container,
        **kwargs,
    ):
        self.corefile_dir = corefile_dir
        self.zones_dir = zones_dir
        self.zones = zones
        self.container = container

        super().__init__(*args, **kwargs)

    def read_json(self, cls):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_data = self.rfile.read(content_length)
        data = json.loads(raw_data)

        # Check if the JSON data contains all the required attributes
        for f in fields(cls):
            if f.name not in data:
                raise ValueError(f"missing attribute '{f.name}' in JSON data.")

        return cls(**data)

    def write(
        self,
        body,
        status_code=STATUS_OK,
        content_type=CONTENT_TYPE_TEXT_PLAIN,
    ):
        self.send_response(status_code)
        self.send_header("Content-type", content_type)
        self.end_headers()

        self.wfile.write(body)

    def not_found(self):
        self.write(b"Not found", status_code=STATUS_NOT_FOUND)

    #
    # Handlers
    #

    def list_zones(self, name=None):
        zones = [z for z in self.zones]

        if name is not None:
            zones = [z for z in zones if z.name == name]

        self.write(
            encode_result(
                [
                    {
                        **{"id": z.id, "name": z.name},
                        **API_CONTAINER_ZONE,
                    }
                    for z in zones
                ]
            ),
            content_type=CONTENT_TYPE_JSON,
        )

    @dataclass
    class CreateZoneRequest:
        name: str

    def create_zone(self):
        req = self.read_json(self.CreateZoneRequest)
        zone = Zone(req.name)
        self.zones.append(zone)

        self.write(
            encode_result({"id": zone.id}),
            content_type=CONTENT_TYPE_JSON,
        )

    def list_dns_records(self, zone_id, name=None):
        z: Zone = next((z for z in self.zones if z.id == zone_id), None)
        if not z:
            raise ValueError(f"zone {zone_id} not found")

        records = [r for r in z.records]

        if name is not None:
            records = [r for r in records if r.name == name]

        self.write(
            encode_result(
                [
                    {
                        **{
                            "id": r.id,
                            "name": r.name,
                            "type": {CNAME: "CNAME", TXT: "TXT"}[type(r)],
                            "content": r.content(),
                            "zone_id": z.id,
                            "zone_name": z.name,
                            "ttl": 1,
                        },
                        **API_CONTAINER_DNS_RECORD,
                    }
                    for r in records
                ]
            ),
            content_type=CONTENT_TYPE_JSON,
        )

    @dataclass
    class CreateDnsRecordRequest:
        type: str
        name: str
        content: str

    def create_dns_record(self, zone_id):
        z: Zone = next((z for z in self.zones if z.id == zone_id), None)
        if not z:
            raise ValueError(f"zone {zone_id} not found")

        req = self.read_json(self.CreateDnsRecordRequest)

        r = {
            "CNAME": CNAME,
            "TXT": TXT,
        }[req.type](
            req.name,
            req.content,
        )

        z.insert(r)

        self.write(
            encode_result(
                {
                    **{
                        "id": r.id,
                        "name": r.name,
                        "type": {CNAME: "CNAME", TXT: "TXT"}[type(r)],
                        "content": r.content(),
                        "zone_id": z.id,
                        "zone_name": z.name,
                        "ttl": 1,
                    },
                    **API_CONTAINER_DNS_RECORD,
                }
            ),
            content_type=CONTENT_TYPE_JSON,
        )

    @dataclass
    class UpdateDnsRecordRequest:
        type: str
        name: str
        content: str

    def update_dns_record(self, zone_id, record_id):
        z: Zone = next((z for z in self.zones if z.id == zone_id), None)
        if not z:
            raise ValueError(f"zone {zone_id} not found")

        req = self.read_json(self.CreateDnsRecordRequest)

        z.update(
            record_id,
            {
                "CNAME": CNAME,
                "TXT": TXT,
            }[req.type](
                req.name,
                req.content,
            ),
        )

        r = z.get(record_id)

        self.write(
            encode_result(
                {
                    **{
                        "id": r.id,
                        "name": r.name,
                        "type": {CNAME: "CNAME", TXT: "TXT"}[type(r)],
                        "content": r.content(),
                        "zone_id": z.id,
                        "zone_name": z.name,
                        "ttl": 1,
                    },
                    **API_CONTAINER_DNS_RECORD,
                }
            ),
            content_type=CONTENT_TYPE_JSON,
        )

    def delete_dns_record(self, zone_id, record_id):
        z: Zone = next((z for z in self.zones if z.id == zone_id), None)
        if not z:
            raise ValueError(f"zone {zone_id} not found")

        z.delete(record_id)

        self.write(
            encode_result({"id": record_id}),
            content_type=CONTENT_TYPE_JSON,
        )

    #
    # Routes
    #

    def route(self, route_handlers):
        for route, handler in route_handlers.items():
            match = re.search(route, self.path)
            if not match:
                continue

            if isinstance(match.groups(), tuple):
                return handler(*match.groups())

            return handler()

        return self.not_found()

    def do_GET(self):
        return self.route(
            {
                r"^/client/v4/zones(?:\?name=([\w|\-|\.|\_]+))?$": self.list_zones,
                r"^/client/v4/zones/(\w+)/dns_records(?:\?name=([\w|\-|\.|\_]+))?$": self.list_dns_records,
            }
        )

    def do_POST(self):
        return self.route(
            {
                r"^/client/v4/zones$": wrap(
                    with_restart(self.container),
                    with_persist(self.corefile_dir, self.zones_dir, self.zones),
                )(self.create_zone),
                r"^/client/v4/zones/(\w+)/dns_records$": wrap(
                    with_restart(self.container),
                    with_persist(self.corefile_dir, self.zones_dir, self.zones),
                )(self.create_dns_record),
            }
        )

    def do_PUT(self):
        return self.route(
            {
                r"^/client/v4/zones/(\w+)/dns_records/(\w+)$": wrap(
                    with_restart(self.container),
                    with_persist(self.corefile_dir, self.zones_dir, self.zones),
                )(self.update_dns_record)
            }
        )

    def do_DELETE(self):
        return self.route(
            {
                r"^/client/v4/zones/(\w+)/dns_records/(\w+)$": wrap(
                    with_restart(self.container),
                    with_persist(self.corefile_dir, self.zones_dir, self.zones),
                )(self.delete_dns_record)
            }
        )


corefile_dir = "/"
zones_dir = "zones"
zones = []
container = Container("coredns")

HTTPServer(
    ("", 8000),
    lambda *args, **kwargs: Handler(
        *args,
        corefile_dir=corefile_dir,
        zones_dir=zones_dir,
        zones=zones,
        container=container,
        **kwargs,
    ),
).serve_forever()
