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
            linkhdrlen = 0;
    }
    return linkhdrlen;
}


void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet){

    // Casts the user data to a ProgramArguments pointer.
    ProgramArguments *args = (ProgramArguments *)user;

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

    uint16_t id, flags, qd_count, an_count, ns_count, ar_count;

    if (parse_dns_header(dns_payload, dns_payload_len ,&id, &flags, &qd_count, &an_count, &ns_count, &ar_count) < 0){
        fprintf(stderr, "Failed to parse DNS header!\n");
        return;
    }


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
    }

    int offset = MIN_DNS_HEADER_LEN;
    offset = parse_dns_question(dns_payload, dns_payload_len, offset, qd_count, domain_list, args->domains_file, args->verbose);
    offset = parse_dns_rrs("Answer Section", dns_payload, dns_payload_len, offset, an_count, domain_list, translation_list, args->domains_file, args->translations_file, args->verbose);
    offset = parse_dns_rrs("Authority Section", dns_payload, dns_payload_len, offset, ns_count, domain_list, translation_list, args->domains_file, args->translations_file, args->verbose);
    offset = parse_dns_rrs("Additional Section", dns_payload, dns_payload_len, offset, ar_count, domain_list, translation_list, args->domains_file, args->translations_file, args->verbose);

    if (args->verbose){
        printf("====================\n");
    }

    return;
}

int parse_dns_header(const unsigned char *dns_payload, int dns_payload_len ,uint16_t *id, uint16_t *flags, uint16_t *qd_count,
                        uint16_t *an_count, uint16_t *ns_count, uint16_t *ar_count){
    if (!dns_payload)
    {   
        fprintf(stderr, "DNS payload is NULL!\n");
        return -1;
    }

    if (dns_payload_len < MIN_DNS_HEADER_LEN){
        fprintf(stderr, "Invalid DNS payload length!\n");
        return -1;
    }


    *id = EXTRACT_16BITS(dns_payload, DNS_ID_OFFSET);
    *flags = EXTRACT_16BITS(dns_payload, DNS_FLAGS_OFFSET);
    *qd_count = EXTRACT_16BITS(dns_payload, DNS_QDCOUNT_OFFSET);
    *an_count = EXTRACT_16BITS(dns_payload, DNS_ANCOUNT_OFFSET);
    *ns_count = EXTRACT_16BITS(dns_payload, DNS_NSCOUNT_OFFSET);
    *ar_count = EXTRACT_16BITS(dns_payload, DNS_ARCOUNT_OFFSET);

    return 0;
}

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
                        u_int16_t qd_count, DomainList *domain_list, FILE *domain_file, int verbose){
    if (qd_count == 0) return offset;

    if (verbose){
        printf("[Question Section]\n");
    }

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
        if (verbose){
            printf("%s. %s %s\n", domain_name, dns_class_to_string(qclass) ,dns_type_to_string(qtype));
        }
        // Add the domain name to the list
        if (domain_list != NULL && domain_file != NULL){
            // Write the domain name to the file if it doesn't exist in the list
            if(!(add_domain_name(domain_list, domain_name))){
                fprintf(domain_file, "%s\n", domain_name);
                fflush(domain_file);
            }
        }
    }

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

int parse_dns_rrs(const char *section_name, const unsigned char *dns_payload, int dns_payload_len, int offset, uint16_t rr_count,
                    DomainList *domain_list, TranslationList *translation_list, FILE *domain_file, FILE *translation_file, int verbose){ 

    if (rr_count == 0) return offset;

    if (verbose){
        printf("\n[%s]\n", section_name);
    }

    for (int i = 0; i < rr_count; i++)
    {
        char domain_name[MAX_DOMAIN_NAME_LEN];
        int bytes_consumed = parse_domain_name(dns_payload, dns_payload_len, offset, domain_name);
        if (bytes_consumed < 0){
            fprintf(stderr, "Failed to parse domain name!\n");
            return -1;
        }

        // Move the offset past the domain name
        offset += bytes_consumed;

        // Make sure there is enough space for the TYPE, CLASS, TTL, and RDLENGTH fields
        if (offset + 10 > dns_payload_len){
            fprintf(stderr, "Invalid RR length!\n");
            return -1;
        }

        uint16_t rr_type = EXTRACT_16BITS(dns_payload, offset);
        offset += 2; // Move the offset past the TYPE field

        uint16_t rr_class = EXTRACT_16BITS(dns_payload, offset);
        offset += 2; // Move the offset past the CLASS field

        uint32_t ttl = EXTRACT_32BITS(dns_payload, offset);
        offset += 4; // Move the offset past the TTL field
        
        uint16_t rdlength = EXTRACT_16BITS(dns_payload, offset);
        offset += 2; // Move the offset past the RDLENGTH field

        // Make sure there is enough space for the RDATA field
        if (offset + rdlength > dns_payload_len){
            fprintf(stderr, "Invalid RDATA length!\n");
            return -1;
        }

        // Print the RR
        if (verbose){
            printf("%s. %u %s %s ", domain_name, ttl, dns_class_to_string(rr_class), dns_type_to_string(rr_type));
        }
        // Process the RDATA based on the RR type
        switch (rr_type){
            case 1: // A
            {
                if (rdlength == 4) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, dns_payload + offset, ip_str, sizeof(ip_str));
                    if (verbose){
                        printf("%s\n", ip_str);
                    }

                    // Collect the translation
                    if (translation_list != NULL && translation_file != NULL){
                        if (!(add_translation(translation_list, domain_name, ip_str))){
                            fprintf(translation_file, "%s %s\n", domain_name, ip_str);
                            fflush(translation_file);
                        }
                    }

                    offset += rdlength;
                } else {
                    fprintf(stderr, "Invalid A record length!\n");
                    offset += rdlength;
                }
            }
            break;

            case 2: // NS 
            {   
                char ns_domain_name[MAX_DOMAIN_NAME_LEN];
                int bytes_consumed = parse_domain_name(dns_payload, dns_payload_len, offset, ns_domain_name);
                if (bytes_consumed < 0){
                    fprintf(stderr, "Failed to parse NS domain name!\n");
                    return -1;
                }

                if (verbose){
                    printf("%s\n", ns_domain_name);
                }

                // Collect the domain name
                if (domain_list != NULL && domain_file != NULL){
                    if (!(add_domain_name(domain_list, ns_domain_name))){
                        fprintf(domain_file, "%s\n", ns_domain_name);
                        fflush(domain_file);
                    }
                }

                offset += rdlength;
                break;
                
            }
            case 5: // CNAME 
            {
                char cname_domain_name[MAX_DOMAIN_NAME_LEN];
                int bytes_consumed = parse_domain_name(dns_payload, dns_payload_len, offset, cname_domain_name);
                if (bytes_consumed < 0){
                    fprintf(stderr, "Failed to parse CNAME domain name!\n");
                    return -1;
                }

                if (verbose){
                    printf("%s\n", cname_domain_name);
                }

                // Collect the domain name
                if (domain_list != NULL && domain_file != NULL){
                    if (!(add_domain_name(domain_list, cname_domain_name))){
                        fprintf(domain_file, "%s\n", cname_domain_name);
                        fflush(domain_file);
                    }
                }

                offset += rdlength;
                break;
            }
            break;
            case 6: // SOA
            {
                char mname[MAX_DOMAIN_NAME_LEN];
                int bytes_consumed = parse_domain_name(dns_payload, dns_payload_len, offset, mname);
                if (bytes_consumed < 0){
                    fprintf(stderr, "Failed to parse SOA MNAME!\n");
                    return -1;
                }
                offset += bytes_consumed;

                char rname[MAX_DOMAIN_NAME_LEN];
                bytes_consumed = parse_domain_name(dns_payload, dns_payload_len, offset, rname);
                if (bytes_consumed < 0){
                    fprintf(stderr, "Failed to parse SOA RNAME!\n");
                    return -1;
                }
                offset += bytes_consumed;

                if (offset + 20 > dns_payload_len){
                    fprintf(stderr, "Invalid SOA record length!\n");
                    offset += rdlength;
                    break;
                }

                uint32_t serial = EXTRACT_32BITS(dns_payload, offset);
                offset += 4; // Move the offset past the SERIAL field
                uint32_t refresh = EXTRACT_32BITS(dns_payload, offset);
                offset += 4; // Move the offset past the REFRESH field
                uint32_t retry = EXTRACT_32BITS(dns_payload, offset);
                offset += 4; // Move the offset past the RETRY field
                uint32_t expire = EXTRACT_32BITS(dns_payload, offset);
                offset += 4; // Move the offset past the EXPIRE field
                uint32_t minimum = EXTRACT_32BITS(dns_payload, offset);
                offset += 4; // Move the offset past the MINIMUM field

                if (verbose){
                    printf("%s %s %u %u %u %u %u\n", mname, rname, serial, refresh, retry, expire, minimum);
                }

                // Collect the domain name
                if (domain_list != NULL && domain_file != NULL){
                    if (!(add_domain_name(domain_list, mname))){
                        fprintf(domain_file, "%s\n", mname);
                        fflush(domain_file);
                    }
                    if (!(add_domain_name(domain_list, rname))){
                        fprintf(domain_file, "%s\n", rname);
                        fflush(domain_file);
                    }
                }
                break;
            }

            case 12: // PTR
            {
                char ptr_domain_name[MAX_DOMAIN_NAME_LEN];
                int bytes_consumed = parse_domain_name(dns_payload, dns_payload_len, offset, ptr_domain_name);
                if (bytes_consumed < 0){
                    fprintf(stderr, "Failed to parse PTR domain name!\n");
                    return -1;
                }

                if (verbose){
                    printf("%s\n", ptr_domain_name);
                }

                // Collect the domain name
                if (domain_list != NULL && domain_file != NULL){
                    if (!(add_domain_name(domain_list, ptr_domain_name))){
                        fprintf(domain_file, "%s\n", ptr_domain_name);
                        fflush(domain_file);
                    }
                }

                offset += bytes_consumed;
                break;
            }
            case 15: // MX 
            {   
                // Make sure there is enough space for the PREFERENCE field
                if (rdlength < 3){
                    fprintf(stderr, "Invalid MX record length!\n");
                    offset += rdlength;
                    break;
                }

                uint16_t preference = EXTRACT_16BITS(dns_payload, offset);
                offset += 2; // Move the offset past the PREFERENCE field

                char mx_domain_name[MAX_DOMAIN_NAME_LEN];
                int bytes_consumed = parse_domain_name(dns_payload, dns_payload_len, offset, mx_domain_name);
                if (bytes_consumed < 0){
                    fprintf(stderr, "Failed to parse MX domain name!\n");
                    return -1;
                }

                if (verbose){
                    printf("%u %s\n", preference, mx_domain_name);
                }

                offset += bytes_consumed;
                break;
            }
            case 28: // AAAA
            {
                if (rdlength == 16) {
                    char ip_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, dns_payload + offset, ip_str, sizeof(ip_str));

                    if (verbose){
                        printf("%s\n", ip_str);
                    }

                    // Collect the translation
                    if (translation_list != NULL && translation_file != NULL){
                        if (!(add_translation(translation_list, domain_name, ip_str))){
                            fprintf(translation_file, "%s %s\n", domain_name, ip_str);
                            fflush(translation_file);
                        }
                    }

                    offset += rdlength;
                } else {
                    fprintf(stderr, "Invalid AAAA record length!\n");
                    offset += rdlength;
                }
                break;
            }
            case 33: // SRV
            {
                if (rdlength < 6){
                    fprintf(stderr, "Invalid SRV record length!\n");
                    offset += rdlength;
                    break;
                }

                uint16_t priority = EXTRACT_16BITS(dns_payload, offset);
                offset += 2; // Move the offset past the PRIORITY field
                uint16_t weight = EXTRACT_16BITS(dns_payload, offset);
                offset += 2; // Move the offset past the WEIGHT field
                uint16_t port = EXTRACT_16BITS(dns_payload, offset);
                offset += 2; // Move the offset past the PORT field

                char target[MAX_DOMAIN_NAME_LEN];
                int bytes_consumed = parse_domain_name(dns_payload, dns_payload_len, offset, target);
                if (bytes_consumed < 0){
                    fprintf(stderr, "Failed to parse SRV target!\n");
                    return -1;
                }

                if (verbose){
                    printf("%u %u %u %s\n", priority, weight, port, target);
                }

                // Collect the domain name
                if (domain_list != NULL && domain_file != NULL){
                    if (!(add_domain_name(domain_list, target))){
                        fprintf(domain_file, "%s\n", target);
                        fflush(domain_file);
                    }
                }

                offset += rdlength;
                break;
            }            
            default:
                fprintf(stderr, "Unsupported RR type: %u\n", rr_type);
                offset +=  rdlength;
                break;
        }    
    }
    return offset;
}