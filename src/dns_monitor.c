/**
 * @file dns_monitor.c
 * @brief DNS Monitor main program file.
 * @author Jakub Fukala (xfukal01)
 *
 * This file contains the main function and signal handling for the dns-monitor program.
 */

#include "dns_monitor.h"
#include <string.h>

// Global variable to stop the packet capture
volatile sig_atomic_t stop_capture = 0;

// Global variable to hold the pcap handle
//pcap_t * handle;

void handle_signal() {
    printf("\nReceived Ctrl+C, exiting...\n");
    stop_capture = 1;
}

int main(int argc, char * argv[]) {
        
    ProgramArguments args = parse_arguments(argc, argv);

    // Open domains and translations files if specified
    FILE *domains_file = NULL;
    FILE *translations_file = NULL;

    if (args.domainsfile){
        domains_file = fopen(args.domainsfile, "w");
        if (domains_file == NULL){
            fprintf(stderr, "Couldn't open domains file %s\n", args.domainsfile);
            return 1;
        }
    }

    if (args.translationsfile){
        translations_file = fopen(args.translationsfile, "w");
        if (translations_file == NULL){
            fprintf(stderr, "Couldn't open translations file %s\n", args.translationsfile);
            return 1;
        }
    }

    // Set up signal handling
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGQUIT, handle_signal);

    // Open the pcap handle
    pcap_t *handle = pcap_handle_ctor(args.interface, args.pcapfile);
    if (handle == NULL){
        if (domains_file) fclose(domains_file);
        if (translations_file) fclose(translations_file);
        return 1;
    }




    // Clean up
    pcap_close(handle);
    if (domains_file) fclose(domains_file);
    if (translations_file) fclose(translations_file);

    
    return 0;
}

pcap_t* pcap_handle_ctor(const char *interface, const char* pcap_file){
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask = 0;
    bpf_u_int32 src_ip = 0;

    if (interface != NULL){ // Open the interface

        if (pcap_lookupnet(interface, &src_ip, &mask, errbuf) == PCAP_ERROR){
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
            src_ip = 0;
            mask = 0;
        }

        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL){
            fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
            return NULL;
        }
    } else if (pcap_file != NULL){ // Open the pcap file
        handle = pcap_open_offline(pcap_file, errbuf);
        if (handle == NULL){
            fprintf(stderr, "Couldn't open file %s: %s\n", pcap_file, errbuf);
            return NULL;
        }
        mask = PCAP_NETMASK_UNKNOWN;
    } else { // No interface or pcap file specified
        fprintf(stderr, "No interface or pcap file specified.\n");
        return NULL;
    }

    // Set filter for DNS packets
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";

    if (pcap_compile(handle, &fp, filter_exp, 0, mask) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    // Free the compiled filter
    pcap_freecode(&fp);

    return handle;
}