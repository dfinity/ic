import qs from "querystring";

import CANISTER_ID_ALIASES from "/var/opt/nginx/canister_aliases/canister_id_aliases.js";
import DOMAIN_CANISTER_MAPPINGS from "/var/opt/nginx/domain_canister_mappings.js";

const CANISTER_ID_LENGTH = 27;

const SYSTEM_SUBNET_LEN = 5;
const SYSTEM_SUBNETS_START = [
  "00000000000000000101",
  "00000000000000070101",
  "00000000000000080101",
  "0000000001a000000101",
  "00000000021000000101",
];
const SYSTEM_SUBNETS_END = [
  "00000000000000060101",
  "00000000000000070101",
  "00000000000fffff0101",
  "0000000001afffff0101",
  "00000000021fffff0101",
];

const RFC4648 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const RE_URI = /^\/api\/v2\/canister\/([0-9a-z\-]+)\//;
const RE_HOST = /^([0-9a-zA-Z\-]+)\./;
const RE_URI_HOSTNAME = /^https?\:\/\/([^:\/?#]*)/;

function decodeCanisterId(canister_id) {
  canister_id = canister_id.replaceAll("-", "").toUpperCase();
  let len = canister_id.length;

  let bits = 0
  let value = 0
  let index = 0
  let bytes = new Uint8Array((len * 5 / 8) | 0)

  for (let i = 0; i < len; i++) {
    value = (value << 5) | RFC4648.indexOf(canister_id[i]);
    bits += 5

    if (bits >= 8) {
      bytes[index++] = (value >>> (bits - 8)) & 255
      bits -= 8
    }
  }

  return Array.from(bytes.slice(4)).map(x => x.toString(16).padStart(2, '0'))
    .join('');
}

function resolveCanisterIdFromUri(uri) {
  const m = RE_URI.exec(uri);
  if (!m) {
    return "";
  }

  let with_prefix = m[1].split("--");
  const canister_id = with_prefix[with_prefix.length - 1];
  if (canister_id.length != CANISTER_ID_LENGTH) {
    return "";
  }

  return canister_id;
}

function extractCanisterIdFromHost(host) {
  const m = RE_HOST.exec(host);
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
  const m = RE_URI_HOSTNAME.exec(uri);
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

function isSystemSubnet(r) {
  let canisterId = r.variables.inferred_canister_id;
  if (!canisterId) {
    return "0";
  }

  canisterId = decodeCanisterId(canisterId);

  for (let i = 0; i <= SYSTEM_SUBNET_LEN; i++) {
    if (canisterId >= SYSTEM_SUBNETS_START[i] && canisterId <= SYSTEM_SUBNETS_END[i]) {
      return "1";
    }
  }

  return "0";
}

export default {
  hostCanisterId,
  inferCanisterId,
  isSystemSubnet,
};
