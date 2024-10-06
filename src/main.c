/**
 * @file main.c
 * @brief DNS Monitor main program file.
 * @author Jakub Fukala (xfukal01)
 *
 * This file contains the main function and signal handling for the dns-monitor program.
 */

#include "arg_parser.h"

// Global variable to stop the packet capture
volatile sig_atomic_t stop_capture = 0;

void handle_signal() {
    printf("\nReceived Ctrl+C, exiting...\n");
    stop_capture = 1;
    //Set the signal handler
    //signal(SIGINT, handle_signal);
}

int main(int argc, char * argv[]) {
        
    ProgramArguments args = parse_arguments(argc, argv);

    printf("interface: %s\n", args.interface);
    
    return 0;

}