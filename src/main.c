#include <stdio.h>
#include "utility.h"

int main(int argc, char * argv[]) {
    
    utility_func();
    
    ProgramArguments args = parse_arguments(argc, argv);

    printf("interface: %s\n", args.interface);
    
    return 0;

}