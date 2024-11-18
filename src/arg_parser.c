#include "dns_monitor.h"
#include <getopt.h>


void print_usage() {
    fprintf(stderr,
            "Usage: dns-monitor (-i <interface> | -p <pcapfile>) [FLAGS]\n\n"
            "Switchers:\n"
            "  -d <domains_file>      Enable domain name collection and specify the output file.\n"
            "  -t <translations_file> Enable domain-to-IP translation collection and specify the output file.\n"
            "  -v                    Enable verbose output.\n"
            "  -g                    Enable debug mode.\n"
            "\nExamples:\n"
            "  dns-monitor -i wlan0\n\n"
            "  dns-monitor -p wire.pcap -d domains_file\n"
            "  dns-monitor -i eth0 -v -d domains_file -t translations_file\n"
    );
}
              
ProgramArguments parse_arguments(int argc, char * argv[]){
    ProgramArguments args = {NULL, NULL, 0, NULL, 0, NULL, 0, 0, {NULL}, NULL, {NULL}, NULL};
    int c;
    while ((c = getopt(argc, argv, "i:p:d:t:vg?")) != -1){
        switch (c){
            case 'i':
                if (!optarg){
                    fprintf(stderr, "Missing argument for -i\n");
                }
                args.interface = optarg;
                break;
            case 'p':
                if (!optarg){
                    fprintf(stderr, "Missing argument for -p\n");
                }
                args.pcapfile = optarg;
                break;
            case 'd':
                if (!optarg){
                    fprintf(stderr, "Missing argument for -d\n");
                }
                args.domain_colecting = 1;
                args.domainsfile = optarg;
                break;
            case 't':
                if (!optarg){
                    fprintf(stderr, "Missing argument for -t\n");
                }
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

    // Check for missing mandatory arguments
    if (!args.interface && !args.pcapfile){
        print_usage();
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
        printf("\n");
    }
    return args;
}