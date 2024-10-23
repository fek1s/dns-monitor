/**
 * @file dns_parser.c
 * @brief This file contains functions to parse DNS packets and extract relevant
 * information for monitoring purposes.
 * 
 * @author Jakub Fukala (xfukal01)
 */


#include "dns_monitor.h"

extern volatile sig_atomic_t stop_capture;

void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet){
    if (stop_capture){
        pcap_breakloop((pcap_t *)user);
        return;
    }
}
