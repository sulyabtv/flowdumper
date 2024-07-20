#pragma once

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <chrono>
#include <unordered_map>
#include <vector>

#define NETLINK_SOCK_TARGET_BUFSIZE 1024 * 1024
#define RECV_BUFSIZE 8192
#define FLOWBUF_CACHE_MAX 100

#define IP_VERSION_4 4
#define IP_VERSION_6 6

namespace flowdumper {

struct ct_flow_tuple {
    uint8_t ip_version;
    uint8_t l4proto;
    union {
        uint32_t src_ip_v4;
        in6_addr src_ip_v6;
    };
    union {
        uint32_t dst_ip_v4;
        in6_addr dst_ip_v6;
    };
    union {
        uint16_t src_port;
        struct {
            uint8_t type;
            uint8_t code;
        } icmp;
    };
    union {
        uint16_t dst_port;
        uint16_t icmp_id;
    };

    bool operator==(const ct_flow_tuple& other) const {
        if (ip_version != other.ip_version || l4proto != other.l4proto)
            return false;
        if (ip_version == IP_VERSION_4 &&
            (src_ip_v4 != other.src_ip_v4 || dst_ip_v4 != other.dst_ip_v4))
            return false;
        if (ip_version == IP_VERSION_6 &&
            (src_ip_v6.s6_addr32[0] != other.src_ip_v6.s6_addr32[0] ||
             src_ip_v6.s6_addr32[1] != other.src_ip_v6.s6_addr32[1] ||
             src_ip_v6.s6_addr32[2] != other.src_ip_v6.s6_addr32[2] ||
             src_ip_v6.s6_addr32[3] != other.src_ip_v6.s6_addr32[3] ||
             dst_ip_v6.s6_addr32[0] != other.dst_ip_v6.s6_addr32[0] ||
             dst_ip_v6.s6_addr32[1] != other.dst_ip_v6.s6_addr32[1] ||
             dst_ip_v6.s6_addr32[2] != other.dst_ip_v6.s6_addr32[2] ||
             dst_ip_v6.s6_addr32[3] != other.dst_ip_v6.s6_addr32[3]))
            return false;
        if ((l4proto == IPPROTO_TCP || l4proto == IPPROTO_UDP) &&
            (src_port != other.src_port || dst_port != other.dst_port))
            return false;
        if ((l4proto == IPPROTO_ICMP || l4proto == IPPROTO_ICMPV6) &&
            (icmp.type != other.icmp.type || icmp.code != other.icmp.code ||
             icmp_id != other.icmp_id))
            return false;
        return true;
    }
};

struct ct_flow_tuple_h {
    std::size_t operator()(const ct_flow_tuple& f) const {
        using std::hash;
        using std::size_t;

        size_t h = 0;
        h = combine_hash(h, hash<uint8_t>()(f.ip_version));
        h = combine_hash(h, hash<uint8_t>()(f.l4proto));
        if (f.ip_version == IP_VERSION_4) {
            h = combine_hash(h, hash<uint32_t>()(f.src_ip_v4));
            h = combine_hash(h, hash<uint32_t>()(f.dst_ip_v4));
        } else {
            h = combine_hash(h, hash<uint32_t>()(f.src_ip_v6.s6_addr32[0]));
            h = combine_hash(h, hash<uint32_t>()(f.src_ip_v6.s6_addr32[1]));
            h = combine_hash(h, hash<uint32_t>()(f.src_ip_v6.s6_addr32[2]));
            h = combine_hash(h, hash<uint32_t>()(f.src_ip_v6.s6_addr32[3]));
            h = combine_hash(h, hash<uint32_t>()(f.dst_ip_v6.s6_addr32[0]));
            h = combine_hash(h, hash<uint32_t>()(f.dst_ip_v6.s6_addr32[1]));
            h = combine_hash(h, hash<uint32_t>()(f.dst_ip_v6.s6_addr32[2]));
            h = combine_hash(h, hash<uint32_t>()(f.dst_ip_v6.s6_addr32[3]));
        }
        if (f.l4proto == IPPROTO_TCP || f.l4proto == IPPROTO_UDP) {
            h = combine_hash(h, hash<uint16_t>()(f.src_port));
            h = combine_hash(h, hash<uint16_t>()(f.dst_port));
        } else if (f.l4proto == IPPROTO_ICMP || f.l4proto == IPPROTO_ICMPV6) {
            h = combine_hash(h, hash<uint8_t>()(f.icmp.type));
            h = combine_hash(h, hash<uint8_t>()(f.icmp.code));
            h = combine_hash(h, hash<uint16_t>()(f.icmp_id));
        }

        return h;
    }

    std::size_t combine_hash(std::size_t h1, std::size_t h2) const {
        return ((h1 << 5) - h1) + h2;
    }
};

struct ct_flow {
    time_t start_time;
    time_t end_time;
    ct_flow_tuple flow_tuple;
    uint64_t fwd_pkts;
    uint64_t fwd_bytes;
    uint64_t rev_pkts;
    uint64_t rev_bytes;
};

struct flow_db {
    std::unordered_map<ct_flow_tuple, time_t, ct_flow_tuple_h> new_flows;
    std::vector<ct_flow> finished_flows;
};

inline time_t get_time() {
    return std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
}

}  // namespace flowdumper