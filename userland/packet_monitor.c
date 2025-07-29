#include "libmcpspy.h"
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Packet monitoring state
static int packet_initialized = 0;
static pthread_t packet_thread;
static int packet_running = 0;
static pcap_t* pcap_handle = NULL;

// Packet capture callback
static void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (!g_initialized || !g_config.monitor_packets) {
        return;
    }

    // Parse Ethernet header (14 bytes)
    if (pkthdr->len < 14) {
        return;
    }

    // Parse IP header
    struct iphdr* ip_header = (struct iphdr*)(packet + 14);
    if (ip_header->protocol != IPPROTO_TCP) {
        return; // Only interested in TCP packets
    }

    // Parse TCP header
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ihl * 4));
    int tcp_header_size = tcp_header->doff * 4;
    
    // Get payload
    int ip_header_size = ip_header->ihl * 4;
    int total_header_size = 14 + ip_header_size + tcp_header_size;
    
    if (pkthdr->len <= total_header_size) {
        return; // No payload
    }

    const char* payload = (const char*)(packet + total_header_size);
    int payload_size = pkthdr->len - total_header_size;

    // Check if payload looks like JSON-RPC
    if (!is_jsonrpc_message(payload, payload_size)) {
        return;
    }

    // Create event for packet
    mcp_event_t event = {0};
    event.timestamp = pkthdr->ts.tv_sec;
    event.pid = 0; // Unknown PID for network packets
    strcpy(event.comm, "packet");
    event.transport = TRANSPORT_PACKET;
    event.event_type = EVENT_TYPE_READ; // Treating as read operation
    event.fd = -1; // No file descriptor for packets
    event.size = payload_size;
    event.buf_size = payload_size < MAX_BUF_SIZE ? payload_size : MAX_BUF_SIZE;

    // Copy payload
    memcpy(event.buf, payload, event.buf_size);

    // Get network addresses
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_header->saddr;
    dst_addr.s_addr = ip_header->daddr;
    
    inet_ntop(AF_INET, &src_addr, event.remote_addr, INET_ADDRSTRLEN);
    event.remote_port = ntohs(tcp_header->source);

    mcpspy_log_event(&event);
}

// Packet monitoring thread
static void* packet_monitor_thread(void* arg) {
    if (!pcap_handle) {
        return NULL;
    }

    // Start packet capture loop
    while (packet_running) {
        int result = pcap_dispatch(pcap_handle, 10, packet_callback, NULL);
        if (result < 0) {
            fprintf(stderr, "mcpspy: Packet capture error: %s\n", pcap_geterr(pcap_handle));
            break;
        }
        
        if (result == 0) {
            usleep(10000); // 10ms
        }
    }
    
    return NULL;
}

// Initialize packet capture monitoring
int packet_monitor_init(void) {
    if (packet_initialized) {
        return 0; // Already initialized
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    char* device = NULL;

    // Find default device if not specified
    device = pcap_lookupdev(errbuf);
    if (!device) {
        fprintf(stderr, "mcpspy: Could not find default device: %s\n", errbuf);
        return -1;
    }

    // Open device for packet capture
    pcap_handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "mcpspy: Could not open device %s: %s\n", device, errbuf);
        return -1;
    }

    // Set filter for TCP traffic on common MCP ports
    struct bpf_program filter;
    char filter_exp[] = "tcp and (port 80 or port 443 or port 8080 or port 3000 or port 4000 or port 5000)";
    
    if (pcap_compile(pcap_handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "mcpspy: Could not parse filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return -1;
    }

    if (pcap_setfilter(pcap_handle, &filter) == -1) {
        fprintf(stderr, "mcpspy: Could not install filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
        pcap_freecode(&filter);
        pcap_close(pcap_handle);
        return -1;
    }

    pcap_freecode(&filter);

    // Start packet monitoring thread
    packet_running = 1;
    if (pthread_create(&packet_thread, NULL, packet_monitor_thread, NULL) != 0) {
        fprintf(stderr, "mcpspy: Failed to create packet monitoring thread\n");
        pcap_close(pcap_handle);
        return -1;
    }
    
    packet_initialized = 1;
    return 0;
}

// Cleanup packet monitoring
void packet_monitor_cleanup(void) {
    if (!packet_initialized) {
        return;
    }
    
    packet_running = 0;
    
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);
    }
    
    pthread_join(packet_thread, NULL);
    
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }
    
    packet_initialized = 0;
}