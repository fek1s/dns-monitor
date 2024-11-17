#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "../src/dns_monitor.h" 
#include <string.h>        
#include <stdlib.h>

pcap_t *handle = NULL;
volatile sig_atomic_t stop_capture = 0;

// DNS Parsing Section//
////////////////////////
void test_parse_domain_name(void){
    unsigned char dns_payload[] = {
        3, 'w', 'w', 'w', 
        6, 'g', 'o', 'o', 'g', 'l', 'e', 
        3, 'c', 'o', 'm', 
        0 
    };

    char domain_name[MAX_DOMAIN_NAME_LEN];
    int offset = 0;

    // Parse the domain name
    int bytes_consumed = parse_domain_name(dns_payload, sizeof(dns_payload), offset, domain_name);

    CU_ASSERT_EQUAL(bytes_consumed, sizeof(dns_payload));
    CU_ASSERT_STRING_EQUAL(domain_name, "www.google.com");
}

void test_parse_domain_name_compression(void) {
    unsigned char dns_payload[] = {
        3, 'w', 'w', 'w', 
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 
        3, 'c', 'o', 'm', 
        0, 
        0xc0, 0x00 // Pointer to "www.example.com"
    };
    char domain_name[MAX_DOMAIN_NAME_LEN];
    int offset = 17; // Pointer starts after the original name
    int bytes_consumed = parse_domain_name(dns_payload, sizeof(dns_payload), offset, domain_name);

    CU_ASSERT_STRING_EQUAL(domain_name, "www.example.com");
    CU_ASSERT_EQUAL(bytes_consumed, 2); // Compression pointer uses 2 bytes
}

void test_parse_dns_questions(void) {
    unsigned char dns_payload[] = {
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name
        0x00, 0x01, // QTYPE A
        0x00, 0x01  // QCLASS IN
    };

    DomainList domain_list;
    init_domain_list(&domain_list);

    FILE *domain_file = tmpfile();
    int offset = parse_dns_question(dns_payload, sizeof(dns_payload), 0, 1, &domain_list, domain_file, 0);

    CU_ASSERT(offset > 0); // Ensure parsing succeeded

    free_domain_list(&domain_list);
    fclose(domain_file);
}

void test_parse_dns_rrs_a_and_aaaa(void) {
    unsigned char dns_payload[] = {
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // Name
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x64, // TTL 100
        0x00, 0x04, // RDLENGTH
        192, 168, 1, 1, // RDATA
        0xc0, 0x0c, // Pointer to Name
        0x00, 0x1c, // TYPE AAAA
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x64, // TTL 100
        0x00, 0x10, // RDLENGTH
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x1a, 0x7d, 0xff, 0xfe, 0x9e, 0xc0, 0xd2 // RDATA
    };

    DomainList domain_list;
    TranslationList translation_list;
    init_domain_list(&domain_list);
    init_translation_list(&translation_list);

    FILE *domain_file = tmpfile();
    FILE *translation_file = tmpfile();

    int offset = 0;
    offset = parse_dns_rrs("Answer Section", dns_payload, sizeof(dns_payload), offset, 2,
                           &domain_list, &translation_list, domain_file, translation_file, 0);

    CU_ASSERT(offset > 0); // Check that parsing succeeded

    free_domain_list(&domain_list);
    free_translation_list(&translation_list);
    fclose(domain_file);
    fclose(translation_file);
}

void test_parse_dns_header_valid(void) {
    unsigned char dns_payload[] = {
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT
        0x00, 0x02, // ANCOUNT
        0x00, 0x03, // NSCOUNT
        0x00, 0x04  // ARCOUNT
    };

    uint16_t id, flags, qd_count, an_count, ns_count, ar_count;
    int result = parse_dns_header(dns_payload, &id, &flags, &qd_count, &an_count, &ns_count, &ar_count);

    CU_ASSERT_EQUAL(result, 0);
    CU_ASSERT_EQUAL(id, 0x1234);
    CU_ASSERT_EQUAL(flags, 0x0100);
    CU_ASSERT_EQUAL(qd_count, 1);
    CU_ASSERT_EQUAL(an_count, 2);
    CU_ASSERT_EQUAL(ns_count, 3);
    CU_ASSERT_EQUAL(ar_count, 4);
}

// Domain List Section//
////////////////////////
void test_add_domain_name(void) {
    DomainList list;
    init_domain_list(&list);

    CU_ASSERT_EQUAL(add_domain_name(&list, "example.com"), 0); // New entry
    CU_ASSERT_EQUAL(add_domain_name(&list, "example.com"), 1); // Duplicate entry
    CU_ASSERT_EQUAL(add_domain_name(&list, "example.org"), 0); // New entry

    free_domain_list(&list);
}

void test_add_translation(void) {
    TranslationList list;
    init_translation_list(&list);

    CU_ASSERT_EQUAL(add_translation(&list, "example.com", "1.1.1.1"), 0); // New entry
    CU_ASSERT_EQUAL(add_translation(&list, "example.com", "1.1.1.1"), 1); // Duplicate entry
    CU_ASSERT_EQUAL(add_translation(&list, "example.org", "2.2.2.2"), 0); // New entry

    free_translation_list(&list);
}

// Arg Parser Section//
///////////////////////

/**
 * @brief Test case for parsing command line arguments with interface option.
 *
 * This function tests the parse_arguments function by providing a set of
 * command line arguments that include the interface option (-i) and verbose
 * option (-v). It verifies that the parsed arguments match the expected values.
 *
 */
void test_parse_arguments_interface(void) {
    char *argv[] = {"dns-monitor", "-i", "eth0", "-v", NULL};
    int argc = 4;

    ProgramArguments args = parse_arguments(argc, argv);

    CU_ASSERT_STRING_EQUAL(args.interface, "eth0");
    CU_ASSERT_EQUAL(args.verbose, 1);
    CU_ASSERT_PTR_NULL(args.pcapfile);
    CU_ASSERT_EQUAL(args.domain_colecting, 0);
    CU_ASSERT_EQUAL(args.translation_colecting, 0);
}


/**
 * @brief Test function for parsing arguments with a pcap file.
 *
 * This function tests the parse_arguments function by providing a set of 
 * command-line arguments that include a pcap file and a domains file. 
 * It verifies that the parsed arguments match the expected values.
 *
 */
void test_parse_arguments_pcapfile(void) {
    char *argv[] = {"dns-monitor", "-p", "capture.pcap", "-d", "domains.txt",NULL};
    int argc = 5;

    ProgramArguments args1 = parse_arguments(argc, argv);

    CU_ASSERT_STRING_EQUAL(args1.pcapfile, "capture.pcap");
    CU_ASSERT_STRING_EQUAL(args1.domainsfile, "domains.txt");
    CU_ASSERT_EQUAL(args1.domain_colecting, 1);
    CU_ASSERT_PTR_NULL(args1.interface);
    CU_ASSERT_EQUAL(args1.verbose, 0);
}


/**
 * @brief Test case for parsing arguments when mandatory arguments are missing.
 *
 * This test case verifies the behavior of the parse_arguments function when
 * mandatory arguments such as interface and PCAP file are not provided.
 *
 */
void test_parse_arguments_missing_mandatory(void) {
    char *argv[] = {"dns-monitor", "-v", "-d", "domains.txt",NULL};
    int argc = 4;

    ProgramArguments args = parse_arguments(argc, argv);

    // Expect no interface or PCAP file specified
    CU_ASSERT_PTR_NULL(args.interface);
    CU_ASSERT_PTR_NULL(args.pcapfile);
    CU_ASSERT_EQUAL(args.domain_colecting, 1);
    CU_ASSERT_STRING_EQUAL(args.domainsfile, "domains.txt");
    CU_ASSERT_EQUAL(args.verbose, 1);
}

/**
 * @brief Test function for parsing all command line arguments.
 *
 * This function tests the parse_arguments function by providing a set of
 * command line arguments that include all possible options. It verifies
 * that the parsed arguments match the expected values.
 *
 */
void test_parse_arguments_all_options(void) {
    char *argv[] = {"dns-monitor", "-i", "eth0", "-d", "domains.txt", "-t", "translations.txt", "-v", "-g", NULL};
    int argc = 9;

    ProgramArguments args = parse_arguments(argc, argv);

    CU_ASSERT_STRING_EQUAL(args.interface, "eth0");
    CU_ASSERT_STRING_EQUAL(args.domainsfile, "domains.txt");
    CU_ASSERT_STRING_EQUAL(args.translationsfile, "translations.txt");
    CU_ASSERT_EQUAL(args.domain_colecting, 1);
    CU_ASSERT_EQUAL(args.translation_colecting, 1);
    CU_ASSERT_EQUAL(args.verbose, 1);
    CU_ASSERT_EQUAL(args.debug, 1);
}

int main() {
    CU_initialize_registry();
    CU_pSuite suite = CU_add_suite("DNS Parser Suite", NULL, NULL);
    // DNS Parsing Tests
    CU_add_test(suite, "Test Parse Domain Name", test_parse_domain_name);
    CU_add_test(suite, "Test Parse Domain Name Compression", test_parse_domain_name_compression);
    CU_add_test(suite, "Test Parse DNS Questions", test_parse_dns_questions);
    CU_add_test(suite, "Test Parse DNS RRs A and AAAA", test_parse_dns_rrs_a_and_aaaa);
    CU_add_test(suite, "Test Parse DNS Header Valid", test_parse_dns_header_valid);

    // Domain List Tests
    CU_add_test(suite, "Test Add Domain Name", test_add_domain_name);
    CU_add_test(suite, "Test Add Translation", test_add_translation);

    // Arg Parser Tests
    CU_add_test(suite, "Test Parse Arguments All Options", test_parse_arguments_all_options);


    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    CU_cleanup_registry();
    return 0;
}