#include <stdio.h>
#include "arg_parser.h"

int main(int argc, char * argv[]) {
        
    ProgramArguments args = parse_arguments(argc, argv);

    printf("interface: %s\n", args.interface);
    
    return 0;

}