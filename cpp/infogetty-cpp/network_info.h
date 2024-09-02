#ifndef NETWORK_INFO_H
#define NETWORK_INFO_H

#include <map>
#include <string>
#include <vector>

struct routing_table_entry {
    // Human-readable destination address (may be :: or 0.0.0.0)
    std::string dst;
    size_t dst_len;
    // Human-readable gateway address (may be :: or 0.0.0.0).
    std::string gateway;
    int priority;
    // Network interface name.
    std::string interface;
};

using routing_table = std::vector<routing_table_entry>;

struct interface_addr {
    // Kind of address (AF_INET or AF_INET6 or AF_PACKET for link layer)
    int family;
    // Human-readable address
    std::string address;
};

struct interface_info {
    bool up;
    bool running;
    std::vector<interface_addr> addresses;
};

using interface_addrs = std::map<std::string, interface_info>;

struct network_info {
    interface_addrs ifaces;
    routing_table rttab;
};

network_info
read_network_info();

std::string
format_network_info(const network_info& info);

#endif  // NETWORK_INFO_H
