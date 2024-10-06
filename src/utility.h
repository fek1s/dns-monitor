// supp.h
#ifndef SUPP_H
#define SUPP_H

#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

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

#endif