#include <stdio.h>
#include "utility.h"

int main(int argc, char * argv[]) {
    
    utility_func();
    
    for (int i = 0; i < argc; i++)
    {
        char * arg = argv[i];
        printf("argv[%d] = %s\n", i, arg);
    }
    
    return 0;

}