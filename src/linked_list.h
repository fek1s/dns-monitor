/**
 * @file linked_list.h
 * @brief Header file for the linked list implementation.
 * @author Jakub Fukala (xfukal01)
 * 
 * This file contains the declarations for the linked list implementation used
 * for storing domain names and their translations.
 */


#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include <stdio.h>

/**
 * @brief Node structure for the linked list.
 * 
 */
typedef struct DomainNode {
    char *domain_name;
    struct DomainNode *next;
} DomainNode;

/**
 * @brief Linked list structure.
 * 
 */
typedef struct {
    DomainNode *head;
} DomainList;

/**
 * @brief Node structure for the translation list.
 * 
 */
typedef struct TranslationNode {
    char *domain_name;
    char *translation;
    struct TranslationNode *next;
} TranslationNode;

/**
 * @brief Linked list structure for translations.
 * 
 */
typedef struct {
    TranslationNode *head;
} TranslationList;



/**
 * @brief Initializes a DomainList.
 * 
 * This function sets up the necessary structures and state for a DomainList
 * to be used. It should be called before any other operations are performed
 * on the list.
 * 
 * @param list A pointer to the DomainList to be initialized.
 */
void init_domain_list(DomainList *list);

/**
 * @brief Adds a domain name to the list.
 * 
 * This function adds a domain name to the list. If the domain already exists in the list,
 * it is not added again.
 * 
 * @param list A pointer to the DomainList.
 * @param domain_name The domain name to be added.
 * @return 0 if the domain was added successfully, 1 if the domain already exists.
 */
int add_domain_name(DomainList *list, const char *domain_name);

/**
 * @brief Checks if a domain exists in the list.
 * 
 * This function checks if a domain exists in the list.
 * 
 * @param list is a pointer to the DomainList.
 * @param domain_name The domain name to be checked.
 * @return 1 if the domain exists, 0 if it does not.
 */
int domain_exists(DomainList *list, const char *domain_name);

/**
 * @brief Frees the memory allocated for the DomainList.
 * 
 * This function frees the memory allocated for the DomainList and all its nodes.
 * 
 * @param list A pointer to the DomainList.
 */
void free_domain_list(DomainList *list);


/**
 * @brief Initializes a TranslationList.
 * 
 * This function sets up the necessary structures and state for a TranslationList
 * to be used. It should be called before any other operations are performed
 * on the list.
 * 
 * @param list A pointer to the TranslationList to be initialized.
 */
void init_translation_list(TranslationList *list);

/**
 * @brief Frees the memory allocated for the translation list.
 *
 * This function deallocates all the memory associated with the given
 * TranslationList, including all its nodes and their contents.
 *
 * @param list A pointer to the TranslationList to be freed.
 */

void free_translation_list(TranslationList *list);

/**
 * @brief Checks if a translation exists in the list.
 *
 * This function searches the given translation list to determine if there is
 * an entry that matches the specified domain name and IP address.
 *
 * @param list Pointer to the translation list.
 * @param domain_name The domain name to search for.
 * @param translation The IP address to search for.
 * @return 1 if the translation exists, 0 otherwise.
 */
int translation_exists(TranslationList *list, const char *domain_name, const char *translation);


/**
 * @brief Adds a new translation to the translation list.
 *
 * This function adds a new domain name and its corresponding IP address
 * to the provided translation list.
 *
 * @param list Pointer to the translation list.
 * @param domain_name The domain name to be added.
 * @param ip_address The IP address corresponding to the domain name.
 * @return int Returns 0 on success, or a negative value on error.
 */
int add_translation(TranslationList *list, const char *domain_name, const char *ip_address);


#endif // LINKED_LIST_H