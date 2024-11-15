/**
 * @file linked_list.c
 * @brief This file contains the implementation of the linked list used for 
 * storing domain names and their translations.
 * 
 * @author Jakub Fukala (xfukal01)
 */

#include "linked_list.h"
#include <stdlib.h>
#include <string.h>


void init_domain_list(DomainList *list){
    list->head = NULL;
}

int add_domain_name(DomainList *list, const char *domain_name){

}

int domain_exists(DomainList *list, const char *domain_name){

}


void free_domain_list(DomainList *list){

}

void write_domain_list(DomainList *list, const char *filename){
    
}