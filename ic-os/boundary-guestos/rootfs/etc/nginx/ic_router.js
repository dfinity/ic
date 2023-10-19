import qs from "querystring";

import SUBNET_TABLE from "/var/opt/nginx/ic/ic_routes.js";
import CANISTER_ID_ALIASES from "/var/opt/nginx/canister_aliases/canister_id_aliases.js";
import DOMAIN_CANISTER_MAPPINGS from "/var/opt/nginx/domain_canister_mappings.js";

const CANISTER_ID_LENGTH = 27;

function leftpad(s, len, pad) {
  return (
    len + 1 >= s.length && (s = new Array(len + 1 - s.length).join(pad) + s), s
  );
}

function decodeCanisterId(canister_id) {
  canister_id = canister_id.replace(/-/g, "");
  const RFC4628 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let hex = "";
  let bits = "";
  for (let i = 0; i < canister_id.length; i++) {
    let val = RFC4628.indexOf(canister_id.charAt(i).toUpperCase());
    bits += leftpad(val.toString(2), 5, "0");
  }
  for (let i = 32; i + 4 <= bits.length; i += 4) {
    let chunk = bits.substr(i, 4);
    hex += parseInt(chunk, 2).toString(16);
  }
  return hex;
}

// Find the first row before the given canister_id.
function findSubnet(canisterId, table) {
  let start = 0;
  let end = table.canister_range_starts.length - 1;
  while (start <= end) {
    let mid = Math.floor((start + end) / 2);
    let mid_value = table.canister_range_starts[mid];

    if (mid_value >= canisterId) {
      end = mid - 1;
    } else {
      start = mid + 1;
    }
  }

  return start > 0 && canisterId < table.canister_range_starts[start]
    ? start - 1
    : Math.min(start, table.canister_range_starts.length - 1);
}

function resolveCanisterIdFromUri(uri) {
  const re = /^\/api\/v2\/canister\/([0-9a-z\-]+)\//;
  const m = re.exec(uri);
  if (!m) {
    return "";
  }
  let with_prefix = m[1].split("--");
  const canister_id = with_prefix[with_prefix.length - 1];
  if (canister_id.length != CANISTER_ID_LENGTH) {
    // not a canister id
    return "";
  }
  return canister_id;
}

function extractCanisterIdFromHost(host) {
  const re = /^([0-9a-zA-Z\-]+)\./;
  const m = re.exec(host);
  if (!m) {
    return "";
  }
  let with_prefix = m[1].split("--");
  let canisterId = with_prefix[with_prefix.length - 1];

  // Check if ID is an alias
  if (!!CANISTER_ID_ALIASES[canisterId]) {
    canisterId = CANISTER_ID_ALIASES[canisterId];
  }

  if (canisterId.length != CANISTER_ID_LENGTH) {
    return "";
  }

  return canisterId;
}

function getHostnameFromUri(uri) {
  const re = /^https?\:\/\/([^:\/?#]*)/;
  const m = re.exec(uri);
  if (!m) {
    return "";
  }
  return m[1];
}

function extractCanisterIdFromReferer(r) {
  const refererHeader = r.headersIn.referer;
  if (!refererHeader) {
    return "";
  }

  const refererHost = getHostnameFromUri(refererHeader);
  if (!refererHost) {
    return "";
  }

  const canisterId = extractCanisterIdFromHost(refererHost);
  if (!!canisterId) {
    return canisterId;
  }

  const idx = refererHeader.indexOf("?");
  if (idx == -1) {
    return "";
  }

  const queryParams = qs.parse(refererHeader.substr(idx + 1));
  return queryParams["canisterId"];
}

function hostCanisterId(r) {
  return extractCanisterIdFromHost(r.headersIn.host);
}

function domainToCanisterId(d) {
  return DOMAIN_CANISTER_MAPPINGS[d] || "";
}

function inferCanisterId(r) {
  // Domain
  let canisterId = domainToCanisterId(r.headersIn.host);
  if (!!canisterId) {
    return canisterId;
  }

  // URI
  canisterId = resolveCanisterIdFromUri(r.uri);
  if (!!canisterId) {
    return canisterId;
  }

  // Host
  canisterId = extractCanisterIdFromHost(r.headersIn.host);
  if (!!canisterId) {
    return canisterId;
  }

  // Query param
  canisterId = r.args["canisterId"];
  if (!!canisterId) {
    return canisterId;
  }

  // Referer
  return extractCanisterIdFromReferer(r);
}

function isTableEmpty(r) {
  return !SUBNET_TABLE["canister_subnets"] ? "1" : "";
}

function normalizeSubnetType(typ) {
  return (
    {
      application: "application",
      system: "system",
    }[typ] || ""
  );
}

function route(r) {
  // Canister ID
  let canisterId = inferCanisterId(r);
  if (!canisterId) {
    return "";
  }

  if (!("canister_subnets" in SUBNET_TABLE)) {
    return "";
  }

  canisterId = decodeCanisterId(canisterId);

  // Determine subnet
  const subnetIdx = findSubnet(canisterId, SUBNET_TABLE);
  if (
    canisterId < SUBNET_TABLE.canister_range_starts[subnetIdx] ||
    canisterId > SUBNET_TABLE.canister_range_ends[subnetIdx]
  ) {
    return "";
  }

  const subnetId = SUBNET_TABLE.canister_subnets[subnetIdx];

  const subnetNodeIds = SUBNET_TABLE.subnet_node_ids[subnetId] || [];
  const nodeCount = subnetNodeIds.length;
  if (nodeCount == 0) {
    return "";
  }

  const subnetTypes = SUBNET_TABLE["subnet_types"] || {};
  const subnetType = normalizeSubnetType(subnetTypes[subnetId]);

  // Choose random node
  const nodeIdx = Math.floor(Math.random() * nodeCount);
  const nodeId = subnetNodeIds[nodeIdx];

  return `${nodeId},${subnetId},${subnetType}`;
}

function randomRoute() {
  const canisterSubnets = SUBNET_TABLE.canister_subnets || [];
  const subnetCount = canisterSubnets.length;
  if (subnetCount == 0) {
    return "";
  }

  // Choose random subnet
  const subnetIdx = Math.floor(Math.random() * subnetCount);
  const subnetId = canisterSubnets[subnetIdx];

  const subnetNodeIds = SUBNET_TABLE.subnet_node_ids[subnetId] || [];
  const nodeCount = subnetNodeIds.length;
  if (nodeCount == 0) {
    return "";
  }

  const subnetTypes = SUBNET_TABLE["subnet_types"] || {};
  const subnetType = normalizeSubnetType(subnetTypes[subnetId]);

  // Choose random node
  const nodeIdx = Math.floor(Math.random() * nodeCount);
  const nodeId = subnetNodeIds[nodeIdx];

  return `${subnetId},${subnetType},${nodeId}`;
}

export default {
  hostCanisterId,
  inferCanisterId,
  isTableEmpty,
  randomRoute,
  route,
};
