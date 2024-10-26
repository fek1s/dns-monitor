/**
 * @file dns_parser.c
 * @brief This file contains functions to parse DNS packets and extract relevant
 * information for monitoring purposes.
 * 
 * @author Jakub Fukala (xfukal01)
 */


#include "dns_monitor.h"
#include <pcap.h>
#include <netinet/in.h>       // Include this for IP address structures
#include <netinet/if_ether.h>  // For struct ether_header
#include <netinet/ip.h>        // For struct ip (IPv4 header)
#include <netinet/ip_icmp.h>   // For struct icmp (ICMP header)
#include <netinet/ip6.h>       // For struct ip6_hdr (IPv6 header)
#include <netinet/udp.h>       // For struct udphdr (UDP header)
#include <arpa/inet.h>         // For inet_ntop to convert IP addresses to strings
#include <string.h>            // For memset, memcpy
#include <stdio.h>             // For standard I/O functions


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
    //printf("Packet captured\n");

    
    // Casts the user data to a ProgramArguments pointer.
    ProgramArguments *args = (ProgramArguments *)user;


    // Get the length of the link-layer header
    int linkhdrlen = get_link_header_len();
    if (linkhdrlen == PCAP_ERROR){
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
        const struct iphdr *ip_hdr = (struct iphdr *)ip_header;
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


    // Print the packet information
    printf("Packet captured: %s:%d -> %s:%d\n", src_ip_str, src_port, dst_ip_str, dst_port);
    printf("DNS payload length: %d\n", dns_payload_len);
    printf("DNS payload: ");
    for (int i = 0; i < dns_payload_len; i++){
        printf("%02x ", dns_payload[i]);
    }
    printf("\n\n");

    // Sleep for 2 seconds if the debug flag is set
    if (args->debug){
        sleep(2);
    }
}
