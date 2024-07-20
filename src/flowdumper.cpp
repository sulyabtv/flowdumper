#include "flowdumper.hpp"

#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

namespace flowdumper {

volatile sig_atomic_t exit_signaled = 0;

static void sighandler(__attribute__((unused)) int s) { exit_signaled = 1; }

ct_flow_tuple extract_flow_tuple(nf_conntrack *ct) {
    ct_flow_tuple flow_tuple = {};

    // ip version, src/dest ip addresses
    switch (nfct_get_attr_u8(ct, ATTR_L3PROTO)) {
        case AF_INET:
            flow_tuple.ip_version = IP_VERSION_4;
            flow_tuple.src_ip_v4 = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
            flow_tuple.dst_ip_v4 = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
            break;

        case AF_INET6:
            flow_tuple.ip_version = IP_VERSION_6;
            memcpy(&flow_tuple.src_ip_v6, nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC),
                   sizeof(in6_addr));
            memcpy(&flow_tuple.dst_ip_v6, nfct_get_attr(ct, ATTR_ORIG_IPV6_DST),
                   sizeof(in6_addr));
            break;
    }

    // l4 protocol
    if (nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO)) {
        flow_tuple.l4proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    }

    // src/dest ports OR icmp type/code/id
    switch (flow_tuple.l4proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            flow_tuple.src_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
            flow_tuple.dst_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
            break;

        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            flow_tuple.icmp.type = nfct_get_attr_u8(ct, ATTR_ICMP_TYPE);
            flow_tuple.icmp.code = nfct_get_attr_u8(ct, ATTR_ICMP_CODE);
            flow_tuple.icmp_id = nfct_get_attr_u16(ct, ATTR_ICMP_ID);
            break;
    }

    return flow_tuple;
}

ct_flow build_ct_flow(nf_conntrack *ct, ct_flow_tuple flow_tuple,
                      time_t start_time, time_t end_time) {
    ct_flow flow = {};

    // copy info passed in args
    flow.start_time = start_time;
    flow.end_time = end_time;
    flow.flow_tuple = flow_tuple;

    // extract packet counters
    if (nfct_attr_is_set(ct, ATTR_ORIG_COUNTER_PACKETS)) {
        flow.fwd_pkts = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
    }
    if (nfct_attr_is_set(ct, ATTR_ORIG_COUNTER_BYTES)) {
        flow.fwd_bytes = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
    }
    if (nfct_attr_is_set(ct, ATTR_REPL_COUNTER_PACKETS)) {
        flow.rev_pkts = nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS);
    }
    if (nfct_attr_is_set(ct, ATTR_REPL_COUNTER_BYTES)) {
        flow.rev_bytes = nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES);
    }

    return flow;
}

static int process_netlink_msg(const nlmsghdr *nlh, void *data) {
    flow_db *db = static_cast<flow_db *>(data);

    nf_conntrack *ct = nfct_new();
    if (ct == NULL) {
        std::cerr << "Error: nfct_new failed: " << strerror(errno) << std::endl;
        return MNL_CB_ERROR;
    }

    nfct_nlmsg_parse(nlh, ct);
    ct_flow_tuple flow_tuple = extract_flow_tuple(ct);

    switch (nlh->nlmsg_type & 0xFF) {
        case IPCTNL_MSG_CT_NEW:
            if (auto search = db->new_flows.find(flow_tuple);
                search == db->new_flows.end()) {
                // we don't have it. add
                db->new_flows.insert({flow_tuple, get_time()});
            }
            break;

        case IPCTNL_MSG_CT_DELETE:
            time_t start_time = 0;
            if (auto search = db->new_flows.find(flow_tuple);
                search != db->new_flows.end()) {
                start_time = search->second;
            }
            db->finished_flows.push_back(
                build_ct_flow(ct, flow_tuple, start_time, get_time()));
            db->new_flows.erase(flow_tuple);
            break;
    }

    nfct_destroy(ct);

    return MNL_CB_OK;
}

mnl_socket *init_netlink_socket() {
    mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        return NULL;
    }

    if (mnl_socket_bind(nl,
                        NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY,
                        MNL_SOCKET_AUTOPID) < 0) {
        mnl_socket_close(nl);
        return NULL;
    }
    return nl;
}

void write_output(std::vector<ct_flow> &flows, fs::path &outdir) {
    // Determine output filename based on current date
    char date[std::size("yyyymmdd")];
    time_t time = get_time();
    std::strftime(date, sizeof(date), "%Y%m%d", std::localtime(&time));
    fs::path outpath = fs::path(outdir).append(date);

    std::ofstream outfile(outpath,
                          std::ios::out | std::ios::binary | std::ios::app);
    for (auto &flow : flows) {
        outfile.write(reinterpret_cast<char *>(&flow), sizeof(flow));
    }
    outfile.close();
    flows.clear();
}

}  // namespace flowdumper

int main() {
    using namespace flowdumper;

    // Create "flowdumper" directory under /tmp for writing output
    fs::path outdir = fs::temp_directory_path().append("flowdumper");
    fs::create_directory(outdir);

    // Set up signal handling
    struct sigaction sigact = {};
    sigact.sa_flags = SA_RESTART;
    sigact.sa_handler = sighandler;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);

    // Initialize netlink socket
    mnl_socket *nl = init_netlink_socket();
    if (nl == NULL) {
        std::cerr << "Error: Could not initialize netlink socket: "
                  << strerror(errno) << std::endl;
        return -1;
    }
    size_t nlsockbufsize = NETLINK_SOCK_TARGET_BUFSIZE;
    socklen_t nlsocklen = sizeof(nlsockbufsize);
    setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVBUFFORCE,
               &nlsockbufsize, nlsocklen);
    getsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVBUF, &nlsockbufsize,
               &nlsocklen);
    std::cerr << "Netlink socket buffer size set to " << nlsockbufsize
              << " bytes" << std::endl;

    // Main loop
    flow_db db;
    while (!exit_signaled) {
        char buf[RECV_BUFSIZE];
        int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        if (ret < 0) {
            if (errno == ENOBUFS) {
                std::cerr
                    << "WARNING: We have hit ENOBUFS! Consider increasing "
                       "buffer size using setsockopt as in "
                       "conntrack_tools/conntrack.c"
                    << std::endl;
                continue;
            }
            std::cerr << "Error: mnl_socket_recvfrom returned failure: "
                      << strerror(errno) << std::endl;
            break;
        }

        ret = mnl_cb_run(buf, ret, 0, 0, process_netlink_msg,
                         static_cast<void *>(&db));
        if (ret == -1) {
            std::cerr << "Error: mnl_cb_run returned failure: "
                      << strerror(errno) << std::endl;
            break;
        } else if (db.finished_flows.size() > FLOWBUF_CACHE_MAX) {
            write_output(db.finished_flows, outdir);
        }
    }

    std::cerr << "Attempting to exit gracefully.." << std::endl;
    write_output(db.finished_flows, outdir);
    mnl_socket_close(nl);

    return 0;
}