import qs from 'querystring';
var tables = {};
var default_routing = '{{ default_routing_value }}';

// one of these per ic/testnet (ics)
{% for ic in ics %}
import subnet_table from 'ic_networks/{{ ic }}/ic_router_table.js';
tables['{{ ic }}'] = subnet_table;
{% endfor %}

function to_hex(bytes) {
  return bytes
      .map(function(byte) {
        return (byte & 0xFF).toString(16)
      })
      .join('')
}

function leftpad(s, len, pad) {
  return len + 1 >= s.length && (s = new Array(len + 1 - s.length).join(pad) + s), s
}

function decode_canister_id(canister_id) {
  canister_id = canister_id.replace(/-/g, '');
  var RFC4628 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  var hex = '';
  var bits = '';
  for (var i = 0; i < canister_id.length; i++) {
    var val = RFC4628.indexOf(canister_id.charAt(i).toUpperCase());
    bits += leftpad(val.toString(2), 5, '0')
  }
  for (i = 32; i + 4 <= bits.length; i += 4) {
    var chunk = bits.substr(i, 4);
    hex += parseInt(chunk, 2).toString(16)
  }
  return hex
}

// Find the first row before the given canister_id.
function find_subnet(canister_id, table) {
  var start = 0;
  var end = table.canister_range_starts.length - 1;
  while (start <= end) {
    var mid = Math.floor((start + end) / 2);
    var mid_value = table.canister_range_starts[mid];
    if (mid_value >= canister_id) {
      end = mid - 1;
    } else {
      start = mid + 1;
    }
  }
  if (start > 0 && canister_id < table.canister_range_starts[start]) {
    return start - 1;
  } else {
    return Math.min(start, table.canister_range_starts.length - 1);
  }
}

function resolve_canister_id_from_uri(uri) {
  var re = /^\/api\/v2\/canister\/([0-9a-z\-]+)\//;
  var m = re.exec(uri);
  if (!m) {
    return '';
  }
  var canister_id = m[1];
  if (canister_id.length < 27) {  // not a canister id
    return '';
  }
  return canister_id;
}

function resolve_canister_id_from_host(host) {
  var re = /^([0-9a-zA-Z\-]+)\./
  var m = re.exec(host);
  if (!m) {
    return '';
  }
  var canister_id = m[1];
  if (canister_id.length < 27) {  // not a canister id
    return '';
  }
  return canister_id;
}

function resolve_ci_from_host(host) {
  var pieces = host.split('.');
  if (pieces.length < 3) {
    return '';
  }
  var ic = pieces[pieces.length-3];
  if (ic.length >= 27) {
    // This is a canister_id.
    return '';
  }
  return ic;
}

function get_hostname_from_uri(uri) {
  var re = /^https?\:\/\/([^:\/?#]*)/
  var m = re.exec(uri);
  if (!m) {
    return '';
  }
  return m[1];
}

function route(r) {
  var ic = resolve_ci_from_host(r.headersIn.host);
  var canister_id = resolve_canister_id_from_uri(r.uri);
  if (!canister_id) {
    canister_id = resolve_canister_id_from_host(r.headersIn.host);
  }
  if (!canister_id) {
    canister_id = r.args['canisterId'];
  }
  var referer = r.headersIn.referer;
  if (!canister_id && referer) {
    var host = get_hostname_from_uri(referer);
    if (host) {
      canister_id = resolve_canister_id_from_host(host);
      if (canister_id) {
        ic = resolve_ci_from_host(host);
      }
    }
    if (!canister_id) {
      var i = referer.indexOf('?');
      if (i >= 0) {
        var args = referer.substring(i + 1);
        canister_id = qs.parse(args)['canisterId'];
      }
    }
  }
  if (ic == '' || !(ic in tables)) {
    ic = default_routing;
  }
  if (!(ic in tables)) {
    return '';
  }
  // TODO: Lookup custom domain via ci
  // if (!canister_id && ci) {
  //   var custom_route = lookup_custom_route(ci);
  //   if (custom_route) {
  //     canister_id = custom_route.canister_id;
  //     ic = custom_route.ic;
  //   }
  // }
  var table = tables[ic];
  if (!("canister_subnets" in table)) {
    return '';
  }
  var subnet_index = 0;
  var status_re = /^\/api\/v2\/status/
  if (r.uri.match(status_re)) { 
    subnet_index = Math.floor(Math.random() * Math.floor(table.canister_subnets.length));
  } else {
    if (!canister_id) {
      return '';
    }
    canister_id = decode_canister_id(canister_id);
    subnet_index = find_subnet(canister_id, table);
    if (canister_id < table.canister_range_starts[subnet_index] ||
        canister_id > table.canister_range_ends[subnet_index]) {
      return '';
    }
  }
  var subnet_id = table.canister_subnets[subnet_index];
  var nodes = table.subnet_nodes[subnet_index];
  if (nodes.length < 1) {
    return '';
  }
  var node_index = Math.floor(Math.random() * Math.floor(nodes.length));
  var node_ids = table.subnet_node_ids[subnet_index];
  var node_id = node_ids[node_index]
  r.headersOut['x-ic-subnet-id'] = subnet_id;
  r.headersOut['x-ic-node-id'] = node_id;
  if (canister_id) {
    r.headersOut['x-ic-canister-id'] = canister_id;
  }
  return node_id.concat(',', subnet_id);
}

export default { route }
