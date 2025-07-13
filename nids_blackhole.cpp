// nids_blackhole.cpp
#include <pcap.h>
#include <map>
#include <csignal>
#include <cstdlib>

std::map<std::string,int> counts;
const int THRESH = 100;

void block_ip(const std::string &ip) {
    std::string cmd = "iptables -A INPUT -s " + ip + " -j DROP";
    system(cmd.c_str());
}

void packet_handler(u_char*, const struct pcap_pkthdr* h, const u_char* bytes) {
    if (h->caplen < 34) return;
    const u_char *ip = bytes + 26;
    char src[16];
    snprintf(src, sizeof(src), "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
    auto &cnt = counts[src];
    if (++cnt == THRESH) block_ip(src);
}

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (!handle) { perror(errbuf); return 1; }
    pcap_loop(handle, 0, packet_handler, nullptr);
    return 0;
}
