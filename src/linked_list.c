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
#include <stdio.h>


void init_domain_list(DomainList *list){
    list->head = NULL;
}

int add_domain_name(DomainList *list, const char *domain_name){
    if (domain_exists(list, domain_name)){
        return 1; // Domain already exists
    }

    DomainNode *new_node = (DomainNode *)malloc(sizeof(DomainNode));
    if (new_node == NULL){
        fprintf(stderr, "Couldn't allocate memory for domain node!\n");
        return -1;
    }

    new_node->domain_name = strdup(domain_name);
    if (new_node->domain_name == NULL){
        fprintf(stderr, "Couldn't allocate memory for domain name!\n");
        free(new_node);
        return -1;
    }
    
    new_node->next = list->head;
    list->head = new_node;

    return 0; // Success
}

int domain_exists(DomainList *list, const char *domain_name){
    DomainNode *current = list->head;
    while (current != NULL){
        if (strcmp(current->domain_name, domain_name) == 0){
            return 1; // Domain exists
        }
        current = current->next;
    }
    return 0; // Domain doesn't exist
}


void free_domain_list(DomainList *list){
    DomainNode *current = list->head;
    while (current != NULL){
        DomainNode *temp = current;
        current = current->next;
        free(temp->domain_name);
        free(temp);
    }
    list->head = NULL;
}


void init_translation_list(TranslationList *list){
    list->head = NULL;
}

void free_translation_list(TranslationList *list){
    TranslationNode *current = list->head;
    while (current != NULL){
        TranslationNode *temp = current;
        current = current->next;
        free(temp->domain_name);
        free(temp->translation);
        free(temp);
    }
    list->head = NULL;
}