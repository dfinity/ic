// This file should have a mime type of `application/x-ns-proxy-autoconfig`
var domains = ["*.localhost", "*.testic0.app"];
function FindProxyForURL(url, host) {
    for (let domain of domains) {
        if (shExpMatch(host, domain)) {
            return "PROXY 127.0.0.1:8123";
        }
    }
    return "DIRECT";
}
