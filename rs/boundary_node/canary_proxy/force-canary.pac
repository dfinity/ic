// This file should have a mime type of `application/x-ns-proxy-autoconfig`
var domains = ["*.ic0.app", "*.icp0.io", "*.icp-api.io", "internetcomputer.org"];
function FindProxyForURL(url, host) {
    for (let domain of domains) {
        if (shExpMatch(host, domain)) {
            return "PROXY canary.boundary.dfinity.network:8888";
        }
    }
    return "DIRECT";
}
