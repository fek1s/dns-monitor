#include <stdio.h>
#include "dns_monitor.h"
#include <getopt.h>


void print_usage(){
    fprintf(stderr, "Použití: dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]\n");
    //exit(EXIT_FAILURE);
    return;
}               

ProgramArguments parse_arguments(int argc, char * argv[]){
    ProgramArguments args = {NULL, NULL, 0, NULL, 0, NULL, 0, 0, {NULL}, NULL, {NULL}, NULL};
    int c;
    while ((c = getopt(argc, argv, "i:p:d:t:vg")) != -1){
        switch (c){
            case 'i':
                args.interface = optarg;
                break;
            case 'p':
                args.pcapfile = optarg;
                break;
            case 'd':
                args.domain_colecting = 1;
                args.domainsfile = optarg;
                break;
            case 't':
                args.translation_colecting = 1;
                args.translationsfile = optarg;         
                break;
            case 'v':
                args.verbose = 1;
                break;
            case 'g':
                args.debug = 1;
                break;
            case '?':
                print_usage();
                break;
            default:
                print_usage();
                break;
        }
    }

    if (args.debug){
        if ((args.interface && args.pcapfile) || (!args.interface && !args.pcapfile)){
            print_usage();
        }

        if (args.interface){
            printf("interface: %s\n", args.interface);
        } else {
            printf("pcapfile: %s\n", args.pcapfile);
        }

        if (args.domainsfile){
            printf("domainsfile: %s\n", args.domainsfile);
        }

        if (args.translationsfile){
            printf("translationsfile: %s\n", args.translationsfile);
        }

        if (args.verbose){
            printf("Verbose option enabled\n");
        } 
    }
    return args;
}