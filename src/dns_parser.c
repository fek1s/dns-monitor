/**
 * @file dns_parser.c
 * @brief This file contains functions to parse DNS packets and extract relevant
 * information for monitoring purposes.
 * 
 * @author Jakub Fukala (xfukal01)
 */


#include "dns_monitor.h"
#include "linked_list.h"
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

    // TODO 
    DomainList *domain_list = args->domainsfile ? &args->domain_list : NULL;
    TranslationList *translation_list = args->translationsfile ? &args->translation_list : NULL;


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
    proccees_dns_packet(dns_payload, dns_payload_len, src_ip_str, dst_ip_str, src_port, dst_port,
                        args, domain_list,
                        translation_list, 
                        header->ts);

    // Sleep for 2 seconds if the debug flag is set
    if (args->debug){
        sleep(1);
    }
}

void proccees_dns_packet(const unsigned char *dns_payload, int dns_payload_len, const char *src_ip_str, 
                        const char *dst_ip_str, uint16_t src_port, uint16_t dst_port, const ProgramArguments *args, 
                        DomainList *domain_list,TranslationList *translation_list ,const struct timeval ts){


    if (dns_payload_len < MIN_DNS_HEADER_LEN)
    {
        fprintf(stderr, "DNS payload is too short for parsing!\n");
        return;
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

    if (args->verbose == 0){
        // Simple output
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

        int offset = MIN_DNS_HEADER_LEN;

        char domain_name[MAX_DOMAIN_NAME_LEN];
        parse_domain_name(dns_payload, dns_payload_len, offset, domain_name);
        //printf("Domain: %s\n", domain_name);
        
        if (args->translation_colecting){
            if (!(add_translation(translation_list, domain_name, src_ip_str))){
                fprintf(args->translations_file, "%s %s\n", domain_name, src_ip_str);
            }
            
        }
        
        offset = parse_dns_question(dns_payload, dns_payload_len, offset, qd_count, domain_list, args->domains_file);
        printf("%d\n", offset);

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

/**
 * @brief Parses the domain name from the DNS payload.
 * 
 * This function extracts the domain name from the DNS payload starting at the given offset.
 * @param dns_payload Pointer to the DNS payload.
 * @param dns_payload_len Length of the DNS payload.
 * @param offset Offset in the DNS payload where the domain name starts.
 * @param domain_name Pointer to a buffer where the domain name will be stored.
 */
int parse_domain_name(const unsigned char *dns_payload, int dns_payload_len, int offset, char *domain_name){
    int offset_start = offset;
    int domain_name_len = 0;
    int jumped = 0; // Flag to indicate if a jump was made
    int pointer_count = 0; // Number of pointers encountered
    int bytes_consumed = 0; // Number of bytes consumed

    while (offset < dns_payload_len){
        uint8_t label_len = dns_payload[offset];

        if ((label_len & 0xC0) == 0xC0){
            // Pointer
            /////////////////////////

            if (offset + 1 >= dns_payload_len){
                fprintf(stderr, "Invalid pointer offset!\n");
                return -1;
            }
            
        
            if (pointer_count >= 5){
                fprintf(stderr, "Too many pointers encountered!\n");
                return -1;
            }

            // Calculate the pointer offset
            uint16_t pointer = ((label_len & 0x3F) << 8) | dns_payload[offset + 1];
            if (pointer >= dns_payload_len){
                fprintf(stderr, "Invalid pointer offset!\n");
                return -1;
            }

            if (!jumped){
                bytes_consumed = offset - offset_start + 2; // Calculate the number of bytes consumed
            }

            offset = pointer;
            jumped = 1;
            pointer_count++;
            //continue;   
        } else if (label_len == 0){
            // End of domain name
            offset++;
            if (!jumped){
                bytes_consumed = offset - offset_start; // Calculate the number of bytes consumed
            }
            break;

        } else {
            // Label

            offset++;

            if (offset + label_len > dns_payload_len){
                fprintf(stderr, "Invalid label length!\n");
                return -1;
            }

            if (domain_name_len + label_len + 1 >= MAX_DOMAIN_NAME_LEN){
                fprintf(stderr, "Domain name is too long!\n");
                return -1;
            }

            // Append dot if not the first label
            if (domain_name_len > 0){
                domain_name[domain_name_len] = '.';
                domain_name_len++;
            }

            // Copy the label to the domain name
            memcpy(domain_name + domain_name_len, dns_payload + offset, label_len);
            domain_name_len += label_len;
            offset += label_len;

            if (!jumped){
                bytes_consumed = offset - offset_start; // Calculate the number of bytes consumed
            }
        }
    }   

    domain_name[domain_name_len] = '\0'; // Null-terminate the domain name

    return bytes_consumed;
}

int parse_dns_question(const unsigned char *dns_payload, int dns_payload_len, int offset, 
                        u_int16_t qd_count, DomainList *domain_list, FILE *domain_file){
    if (qd_count == 0) return offset;

    printf("[Question Section]\n");

    for (int i = 0; i < qd_count; i++){
        char domain_name[MAX_DOMAIN_NAME_LEN];
        int bytes_consumed = parse_domain_name(dns_payload, dns_payload_len, offset, domain_name);
        if (bytes_consumed < 0){
            fprintf(stderr, "Failed to parse domain name!\n");
            return -1;
        }

        // Move the offset past the domain name
        offset += bytes_consumed;

        // Make sure there is enough space for the QTYPE and QCLASS fields
        if (offset + 4 > dns_payload_len){
            fprintf(stderr, "Invalid question section length!\n");
            return -1;
        }

        uint16_t qtype = EXTRACT_16BITS(dns_payload, offset);
        offset += 2; // Move the offset past the QTYPE field
        uint16_t qclass = EXTRACT_16BITS(dns_payload, offset);
        offset += 2; // Move the offset past the QCLASS field

        // Print the question
        printf("%s %s %s\n", domain_name, dns_class_to_string(qclass) ,dns_type_to_string(qtype));

        // Add the domain name to the list
        if (domain_list != NULL && domain_file != NULL){
            // Write the domain name to the file if it doesn't exist in the list
            if(!(add_domain_name(domain_list, domain_name))){
                fprintf(domain_file, "%s\n", domain_name);
                fflush(domain_file);
            }
        }
    }

    printf("\n");
    return offset;
}

char *dns_type_to_string(uint16_t qtype){
    switch (qtype) {
        case 1:
            return "A";          // IPv4 address
        case 2:
            return "NS";         // Authoritative Name Server
        case 5:
            return "CNAME";      // Canonical Name
        case 6:
            return "SOA";        // Start of a zone of authority
        case 12:
            return "PTR";        // Domain name pointer
        case 15:
            return "MX";         // Mail exchange
        case 16:
            return "TXT";        // Text records
        case 28:
            return "AAAA";       // IPv6 address
        case 33:
            return "SRV";        // Service locator
        case 35:
            return "NAPTR";      // Naming Authority Pointer
        case 39:
            return "DNAME";      // Delegation Name
        case 41:
            return "OPT";        // Option
        case 43:
            return "DS";         // Delegation Signer
        case 46:
            return "RRSIG";      // DNSSEC signature
        case 47:
            return "NSEC";       // Next Secure record
        case 48:
            return "DNSKEY";     // DNS Key record
        case 257:
            return "CAA";        // Certification Authority Authorization
        case 252:
            return "AXFR";       // Request for a zone transfer
        case 255:
            return "ANY";        // All cached records
        default:
            return "Unknown";    // Unknown or unsupported type
    }
}

const char* dns_class_to_string(uint16_t qclass) {
    switch (qclass) {
        case 1:
            return "IN";
        case 3:
            return "CH";
        case 4:
            return "HS";
        case 254:
            return "NONE";
        case 255:
            return "ANY";
        default:
            return "Unknown";
    }
}
