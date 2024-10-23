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
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <pcap/pcap.h>

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

#endif // DNS_MONITOR_H