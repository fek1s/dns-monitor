/**
 * @file dns_parser.c
 * @brief This file contains functions to parse DNS packets and extract relevant
 * information for monitoring purposes.
 * 
 * @author Jakub Fukala (xfukal01)
 */


#include "dns_monitor.h"
#include <time.h>

// Global variable to stop the packet capture
extern volatile sig_atomic_t stop_capture;

// Global variable to hold the pcap handle
extern pcap_t *handle;


int get_link_header_len() {
    int linktype = pcap_datalink(handle);
    int linkhdrlen = 0;
    if (linktype == PCAP_ERROR) {
        fprintf(stderr, "pcap_datalink(): %s\n", pcap_geterr(handle));
        linkhdrlen = 0;
        return PCAP_ERROR;
    }

    switch (linktype) {
        case DLT_NULL:
            linkhdrlen = 4;
            break;
        case DLT_EN10MB:
            linkhdrlen = 14;
            break;
        case DLT_SLIP:
        case DLT_PPP:
            linkhdrlen = 24;
            break;
        default:
            printf("Unsupported datalink type (%d)\n", linktype);
            linkhdrlen = 0;
    }
    return linkhdrlen;
}


void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet){
    if (stop_capture){
        printf("Stopping packet capture\n");
        pcap_breakloop(handle);
        return;
    }

    // Casts the user data to a ProgramArguments pointer.
    ProgramArguments *args = (ProgramArguments *)user;


    // Get the length of the link-layer header
    int linkhdrlen = get_link_header_len();
    if (linkhdrlen == PCAP_ERROR){
        fprintf(stderr, "Failed to determine link-layer header length.\n");
        return;
    }

    // Skip the link layer header
    const unsigned char *ip_header = packet + linkhdrlen;

    // Cast the IP header
    const struct iphdr *ip_hdr = (struct iphdr *)ip_header;

    // Get the IP version
    uint8_t ip_version = ip_hdr->version; 


    // Declare pointers to the UDP header and DNS payload
    const struct udphdr *udphdr = NULL;
    const unsigned char *dns_payload = NULL;
    int dns_payload_len = 0;

    // Declare variables to store IP addresses and ports
    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    if (ip_version == 4){
        // IPv4 
        int ip_hdr_len = ip_hdr->ihl * 4; // Length of the IP header in bytes

        // Make sure the packet is UDP
        if (ip_hdr->protocol != IPPROTO_UDP){
            return; // Not a UDP packet
        }

        // Get the DNS payload from the UDP packet
        udphdr = (struct udphdr *)(ip_header + ip_hdr_len);
        dns_payload = (unsigned char *)udphdr + sizeof(struct udphdr);
        dns_payload_len = ntohs(udphdr->len) - sizeof(struct udphdr);

        // Convert IP addresses to strings
        inet_ntop(AF_INET, &ip_hdr->saddr, src_ip_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip_str, INET6_ADDRSTRLEN);

    } else if (ip_version == 6) {
        // IPv6
        const struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ip_header;

        // Make sure the packet is UDP
        if (ip6_hdr->ip6_nxt != IPPROTO_UDP){
            return; // Not a UDP packet
        }

        // Get the DNS payload from the UDP packet
        udphdr = (struct udphdr *)(ip_header + sizeof(struct ip6_hdr));
        dns_payload = (unsigned char *)udphdr + sizeof(struct udphdr);
        dns_payload_len = ntohs(udphdr->len) - sizeof(struct udphdr);

        // Convert IP addresses to strings
        inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_ip_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst_ip_str, INET6_ADDRSTRLEN);
        
    } else 
    {
        return; // Not an IPv4 or IPv6 packet
    }

    // Get the source and destination ports
    src_port = ntohs(udphdr->source);
    dst_port = ntohs(udphdr->dest);


    // Process the DNS packet
    proccees_dns_packet(dns_payload, dns_payload_len, src_ip_str, dst_ip_str, src_port, dst_port, args->verbose, header->ts);

    // Sleep for 2 seconds if the debug flag is set
    if (args->debug){
        //printf("Sleeping for 2 seconds...\n");
        sleep(2);
    }
}

void proccees_dns_packet(const unsigned char *dns_payload, int dns_payload_len, const char *src_ip_str, const char *dst_ip_str,
                        uint16_t src_port, uint16_t dst_port, int verbose, const struct timeval ts){


    if (dns_payload_len < MIN_DNS_HEADER_LEN)
    {
        fprintf(stderr, "DNS payload is too short for parsing!\n");
    }

    uint16_t id, flags, qd_count, an_count, ns_count, ar_count;

    parse_dns_header(dns_payload, &id, &flags, &qd_count, &an_count, &ns_count, &ar_count);


    // Get the timestamp
    char timestamp[64];
    struct tm *tm_info = localtime(&ts.tv_sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // Extract the flags
    int qr = GET_QR(flags);
    int opcode = GET_OPCODE(flags);
    int aa = GET_AA(flags);
    int tc = GET_TC(flags);
    int rd = GET_RD(flags);
    int ra = GET_RA(flags);
    int ad = GET_AD(flags);
    int cd = GET_CD(flags);
    int rcode = GET_RCODE(flags);

    if (!verbose){
        // Non-verbose output
        printf("%s %s -> %s (%c %d/%d/%d/%d)\n",
                timestamp, src_ip_str, dst_ip_str, 
                qr ? 'R' : 'Q', // 1 for response, 0 for query
                qd_count, an_count, ns_count, ar_count);
                
        printf("\n");

        return;
    } else {
        // Verbose output
        printf("Timestamp: %s\n", timestamp);
        printf("SrcIP: %s\n", src_ip_str);
        printf("DstIP: %s\n", dst_ip_str);
        printf("SrcPort: UDP/%d\n", src_port);
        printf("DstPort: UDP/%d\n", dst_port);
        printf("Identifier: 0x%04X\n", id);
        printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
               qr, opcode, aa, tc, rd, ra, ad, cd, rcode);
        printf("\n");

        return;
    }
}

void parse_dns_header(const unsigned char *dns_payload, uint16_t *id, uint16_t *flags, uint16_t *qd_count,
                        uint16_t *an_count, u_int16_t *ns_count, uint16_t *ar_count){
    if (!dns_payload)
    {   
        fprintf(stderr, "DNS payload is NULL!\n");
        return;
    }

    *id = EXTRACT_16BITS(dns_payload, DNS_ID_OFFSET);
    *flags = EXTRACT_16BITS(dns_payload, DNS_FLAGS_OFFSET);
    *qd_count = EXTRACT_16BITS(dns_payload, DNS_QDCOUNT_OFFSET);
    *an_count = EXTRACT_16BITS(dns_payload, DNS_ANCOUNT_OFFSET);
    *ns_count = EXTRACT_16BITS(dns_payload, DNS_NSCOUNT_OFFSET);
    *ar_count = EXTRACT_16BITS(dns_payload, DNS_ARCOUNT_OFFSET);
}
