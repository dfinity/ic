#include "network_info.h"

#include <arpa/inet.h>
#include <chrono>
#include <ifaddrs.h>
#include <iomanip>
#include <linux/if_packet.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <systemd/sd-journal.h>
#include <unistd.h>


#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <sstream>
#include <vector>
#include <unordered_map>

#include <iostream>

namespace {

void
check_panic_errno(int return_code, const char* info)
{
    if (return_code >= 0) {
        return;
    }

    std::string message = std::string("infogetty: ") + info + ": " + strerror(errno);
    sd_journal_print(LOG_ERR, "%s", message.c_str());
    _exit(1);
}

// Registry of network interfaces, to avoid repeatedly looking up interface
// name by index. (Instead of cached lookups could also maybe just pre-populate
// the table via netlink).
class ifregistry {
public:
    const std::string&
    get_name(int index);

    bool
    is_virtual(const std::string& name);

private:
    std::map<int, std::string> index_to_name_;
    std::map<std::string, int> name_to_index_;
    std::unordered_map<std::string, bool> is_virtual_cached_;
};

const std::string&
ifregistry::get_name(int index)
{
    auto i = index_to_name_.find(index);
    if (i == index_to_name_.end()) {
        char tmp[IF_NAMESIZE];
        char* res = if_indextoname(index, tmp);
        if (!res) {
            static const std::string NO_IF = "(none)";
            return NO_IF;
        }
        i = index_to_name_.emplace(index, tmp).first;
        name_to_index_[tmp] = index;
    }
    return i->second;
}

bool
ifregistry::is_virtual(const std::string& name)
{
    auto i = is_virtual_cached_.find(name);
    if (i == is_virtual_cached_.end()) {
        char tmp[1024];
        ssize_t sz = ::readlink(("/sys/class/net/" + name).c_str(), tmp, sizeof(tmp) - 1);
        bool is_virtual = true;
        if (sz > 0) {
            auto tmpstr = std::string_view(tmp, sz);
            is_virtual = (tmpstr.substr(0, 22) == "../../devices/virtual/");
        }
        i = is_virtual_cached_.emplace(name, is_virtual).first;
    }
    return i->second;
}

std::string
format_addr(int af, const void* src, std::size_t len)
{
    char tmp[100];
    if (af == AF_INET && len == 4) {
        inet_ntop(AF_INET, src, tmp, sizeof(tmp));
        return tmp;
    } else if (af == AF_INET6 && len == 16) {
        inet_ntop(AF_INET6, src, tmp, sizeof(tmp));
        return tmp;
    } else if (af == AF_PACKET && len == 6) {
        ether_ntoa_r(reinterpret_cast<const struct ether_addr*>(src), tmp);
        return tmp;
    } else {
        return "(unknown)";
    }
}

std::string
format_sockaddr(const struct sockaddr* sa)
{
    if (!sa) {
        return "(null)";
    } else if (sa->sa_family == AF_INET) {
        const auto& sa_in = reinterpret_cast<const struct sockaddr_in*>(sa);
        return format_addr(AF_INET, &sa_in->sin_addr, sizeof(sa_in->sin_addr));
    } else if (sa->sa_family == AF_INET6) {
        const auto& sa_in6 = reinterpret_cast<const struct sockaddr_in6*>(sa);
        return format_addr(AF_INET6, &sa_in6->sin6_addr, sizeof(sa_in6->sin6_addr));
    } else if (sa->sa_family == AF_PACKET) {
        const auto& sa_ll = reinterpret_cast<const struct sockaddr_ll*>(sa);
        return format_addr(AF_PACKET, &sa_ll->sll_addr, sa_ll->sll_halen);
    } else {
        return "(unknown)";
    }
}

interface_addrs
read_interface_addrs(ifregistry* registry)
{
    interface_addrs result;

    struct ifaddrs* addrs;
    ::getifaddrs(&addrs);

    for (struct ifaddrs* current = addrs; current; current = current->ifa_next) {
        if (registry->is_virtual(current->ifa_name)) {
            continue;
        }
        if (current->ifa_addr) {
            auto &info = result[current->ifa_name];
            info.up = current->ifa_flags & IFF_UP;
            info.running = current->ifa_flags & IFF_RUNNING;
            info.addresses.push_back(interface_addr {
                current->ifa_addr->sa_family,
                format_sockaddr(current->ifa_addr)
            });
        }
    }

    ::freeifaddrs(addrs);
    return result;
}

std::string
default_addr_of_family(int family)
{
    switch (family) {
        case AF_INET: {
            return "0.0.0.0";
        }
        case AF_INET6: {
            return "::";
        }
        default: {
            return "default";
        }
    }
}

class aligned_buffer {
public:
    inline
    aligned_buffer() : buf_(static_cast<char*>(0), std::free)
    {
        resize(4096);
    }

    inline char*
    get()
    {
        return buf_.get();
    }

    inline void
    resize(std::size_t n)
    {
        if (n > capacity_) {
            std::unique_ptr<char[], void(*)(void*)> tmp(
                reinterpret_cast<char*>(aligned_alloc(alignof(struct nlmsghdr), n)),
                std::free);
            std::memcpy(tmp.get(), buf_.get(), capacity_);
            capacity_ = n;
            buf_.swap(tmp);
        }
    }

    inline std::size_t capacity() const { return capacity_; }

private:
    std::unique_ptr<char[], void(*)(void*)> buf_;
    std::size_t capacity_ = 0;
};

ssize_t
send_route_query(int nl_socket, aligned_buffer& buf)
{
    struct sockaddr_nl tgt = {};
    tgt.nl_family = AF_NETLINK;

    struct nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buf.get());
    std::memset(nlh, 0, NLMSG_ALIGN(sizeof(*nlh)));
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_len = NLMSG_ALIGN(sizeof(*nlh));

    struct rtmsg* rt = reinterpret_cast<struct rtmsg*>(buf.get() + nlh->nlmsg_len);
    std::memset(rt, 0, NLMSG_ALIGN(sizeof(*rt)));
    nlh->nlmsg_len += NLMSG_ALIGN(sizeof(*rt));

    return ::sendto(nl_socket, buf.get(), nlh->nlmsg_len, 0, reinterpret_cast<struct sockaddr*>(&tgt), sizeof(tgt));
}

ssize_t
recv_netlink_msg(int nl_socket, aligned_buffer& buf)
{
    ssize_t count = ::recv(nl_socket, buf.get(), buf.capacity(), MSG_TRUNC | MSG_PEEK);
    if (count < 0) {
        return count;
    }
    buf.resize(count);
    return ::recv(nl_socket, buf.get(), buf.capacity(), 0);
}

routing_table
read_routing_table(ifregistry* registry)
{
    // Raw netlink communication, no other way to get routing table.
    struct sockaddr_nl sa = {};
    sa.nl_family = AF_NETLINK;
    int nl_socket = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check_panic_errno(nl_socket, "socket(netlink)");
    check_panic_errno(::bind(nl_socket, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)), "bind(netlink)");

    routing_table rttab;

    aligned_buffer buf;
    check_panic_errno(send_route_query(nl_socket, buf), "send(netlink)");

    bool done = false;
    while (!done) {
        ssize_t received = recv_netlink_msg(nl_socket, buf);
        check_panic_errno(received, "recv(netlink)");

        int remaining_size = received;
        auto nlh = reinterpret_cast<const struct nlmsghdr*>(buf.get());
        while (nlh && remaining_size) {
            const char* pos = reinterpret_cast<const char*>(nlh);
            const char* end = pos + nlh->nlmsg_len;

            pos += NLMSG_ALIGN(sizeof(*nlh));
            switch (nlh->nlmsg_type) {
                case NLMSG_DONE: {
                    done = true;
                    break;
                }
                case RTM_NEWROUTE: {
                    auto rt = reinterpret_cast<const struct rtmsg*>(pos);
                    pos += NLMSG_ALIGN(sizeof(*rt));

                    std::string dst = default_addr_of_family(rt->rtm_family);
                    std::string gateway = default_addr_of_family(rt->rtm_family);
                    std::string interface_name = "";
                    int priority = 0;

                    while (static_cast<std::size_t>(end - pos) > sizeof(nlattr)) {
                        auto nla = reinterpret_cast<const struct nlattr*>(pos);
                        auto payload = pos + NLA_HDRLEN;
                        auto payload_size = nla->nla_len - NLA_HDRLEN;
                        pos += NLA_ALIGN(nla->nla_len);
                        switch (nla->nla_type) {
                            case RTA_DST: {
                                dst = format_addr(rt->rtm_family, payload, payload_size);
                                break;
                            }
                            case RTA_GATEWAY: {
                                gateway = format_addr(rt->rtm_family, payload, payload_size);
                                break;
                            }
                            case RTA_PRIORITY: {
                                if (payload_size == sizeof(int)) {
                                    priority = *reinterpret_cast<const int*>(payload);
                                }
                                break;
                            }
                            case RTA_OIF: {
                                if (payload_size == sizeof(int)) {
                                    int out_interface = *reinterpret_cast<const int*>(payload);
                                    interface_name = registry->get_name(out_interface);
                                }
                                break;
                            }
                        }
                    }

                    // Record the route if it is of interest.
                    if (!registry->is_virtual(interface_name) && rt->rtm_scope == RT_SCOPE_UNIVERSE) {
                        rttab.push_back(routing_table_entry {
                            std::move(dst),
                            rt->rtm_dst_len,
                            std::move(gateway),
                            priority,
                            std::move(interface_name)
                        });
                    }

                    break;
                }
            }
            nlh = NLMSG_NEXT(nlh, remaining_size);
        }
    }

    ::close(nl_socket);

    return rttab;
}

}  // namespace

network_info
read_network_info()
{
    ifregistry registry;
    return network_info {
        read_interface_addrs(&registry),
        read_routing_table(&registry)
    };
}

std::string
format_network_info(const network_info& info)
{
    std::stringstream ss;

    const std::chrono::time_point now = std::chrono::system_clock::now();
    const std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    ss << std::put_time(std::gmtime(&now_time), "%F %T %Z\n");

    for (const auto& iface : info.ifaces) {
        ss << iface.first << (iface.second.up ? " up" : "") << (iface.second.running ? " running" : "");
        for (const auto& addr : iface.second.addresses) {
            ss << " " << addr.address;
        }
        ss << "\n";
    }
    for (const auto& entry : info.rttab) {
        ss << "route " << entry.dst << "/" << entry.dst_len << " gw " << entry.gateway << " iface " << entry.interface << "\n";
    }

    return ss.str();
}
