/**
 * @file dns_monitor.h
 * @brief Header file for argument parsing and signal handling in dns-monitor.
 * @author Jakub Fukala (xfukal01)
 *
 * This file contains the declarations for functions and structures used
 * for parsing command-line arguments and handling signals in the dns-monitor
 * program.
 */


#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <netinet/in.h>       // Include this for IP address structures
#include <netinet/if_ether.h>  // For struct ether_header
#include <netinet/ip.h>        // For struct ip (IPv4 header)
#include <netinet/ip_icmp.h>   // For struct icmp (ICMP header)
#include <netinet/ip6.h>       // For struct ip6_hdr (IPv6 header)
#include <netinet/udp.h>       // For struct udphdr (UDP header)
#include <arpa/inet.h>         // For inet_ntop to convert IP addresses to strings
#include <string.h>            // For memset, memcpy

// Macros for extracting individual bits from the flags field of the DNS header
#define GET_QR(flags)      (((flags) >> 15) & 0x01)
#define GET_OPCODE(flags)  (((flags) >> 11) & 0x0F)
#define GET_AA(flags)      (((flags) >> 10) & 0x01)
#define GET_TC(flags)      (((flags) >> 9) & 0x01)
#define GET_RD(flags)      (((flags) >> 8) & 0x01)
#define GET_RA(flags)      (((flags) >> 7) & 0x01)
#define GET_AD(flags)      (((flags) >> 5) & 0x01)
#define GET_CD(flags)      (((flags) >> 4) & 0x01)
#define GET_RCODE(flags)   ((flags) & 0x0F)

// Macro for extracting 16 bits from a byte array at a given offset
#define EXTRACT_16BITS(data, offset) (((data)[offset] << 8) | (data)[offset + 1])

// Offsets of fields in the DNS header
#define DNS_ID_OFFSET 0
#define DNS_FLAGS_OFFSET 2
#define DNS_QDCOUNT_OFFSET 4
#define DNS_ANCOUNT_OFFSET 6
#define DNS_NSCOUNT_OFFSET 8
#define DNS_ARCOUNT_OFFSET 10

#define MIN_DNS_HEADER_LEN 12


/**
 * @brief Holds the cli arguments passed to the program
 *
 * This structure holds all the necessary parameters that can be
 * passed to the dns-monitor.
 */
typedef struct
{
    char * interface;
    char * pcapfile;
    char * domainsfile;
    char * translationsfile;
    int verbose;
    int debug;
} ProgramArguments;

/**
 * @brief Prints the usage of the program to the standard error.
 */
void print_usage();

/**
 * @brief Parses the command-line arguments provided to the program.
 *
 * This function processes the arguments passed to the program and
 * returns a structure containing the parsed values.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of strings representing the command-line arguments.
 * @return A ProgramArguments structure containing the parsed arguments.
 */
ProgramArguments parse_arguments(int argc, char * argv[]);

/**
 * @brief Handles the SIGINT signal.
 *
 * This function is called when the program receives the SIGINT signal.
 * It sets the global variable stop_capture to 1, which stops the packet
 * capture.
 */
void handle_signal();

/**
 * @brief Creates a pcap handle for capturing packets.
 * 
 * @param interface Network interface to capture packets from.
 * @param pcap_file PCAP file to read packets from.
 * @return Pointer to pcap_t handle, or NULL on failure.
 */
pcap_t* pcap_handle_ctor(const char *interface, const char* pcap_file);


/**
 * @brief Handles the packets captured by the pcap handle.
 * 
 * This function is called for each packet captured by the pcap handle.
 * It processes the packet and prints the relevant information to the
 * standard output.
 * 
 * @param user User data passed to the pcap_loop function.
 * @param pkthdr Packet header containing information about the packet.
 * @param packet Packet data.
 */
void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet);

/**
 * @brief Determines the length of the link-layer header based on the link type.
 *
 * Supported link types and their corresponding header lengths:
 * - DLT_NULL: 4 bytes
 * - DLT_EN10MB: 14 bytes
 * - DLT_SLIP: 24 bytes
 * - DLT_PPP: 24 bytes
 *
 * If the link type is unsupported, an error message is printed and the header length is set to 0.
 *
 * @return The length of the link-layer header in bytes.
 */
int get_link_header_len();

/**
 * @brief Processes the DNS payload of a packet.
 *
 * This function extracts the DNS header and questions from the DNS payload
 * of a packet and prints the information to the standard output.
 *
 * @param dns_payload Pointer to the DNS payload.
 * @param dns_payload_len Length of the DNS payload.
 * @param src_ip_str Source IP address of the packet.
 * @param dst_ip_str Destination IP address of the packet.
 * @param src_port Source port of the packet.
 * @param dst_port Destination port of the packet.
 * @param verbose Flag to enable verbose output.
 * @param ts Timestamp of the packet.
 */
void proccees_dns_packet(const unsigned char *dns_payload, int dns_payload_len, const char *src_ip_str, const char *dst_ip_str, uint16_t src_port, uint16_t dst_port, int verbose, const struct timeval ts);


/**
 * @brief Parses the DNS header from the given DNS payload.
 *
 * This function extracts various fields from the DNS header, including the ID, flags,
 * question count, answer count, authority record count, and additional record count.
 *
 * @param dns_payload Pointer to the DNS payload from which the header will be parsed.
 * @param id Pointer to a variable where the Transaction ID will be stored.
 * @param flags Pointer to a variable where the Flags will be stored.
 * @param qd_count Pointer to a variable where the Number of questions will be stored.
 * @param an_count Pointer to a variable where the Number of answers will be stored.
 * @param ns_count Pointer to a variable where the Number of authority records field will be stored.
 * @param ar_count Pointer to a variable where the Number of additional records will be stored.
 */
void parse_dns_header(const unsigned char *dns_payload, uint16_t *id, uint16_t *flags, uint16_t *qd_count, uint16_t *an_count, u_int16_t *ns_count, uint16_t *ar_count);

#endif // DNS_MONITOR_H