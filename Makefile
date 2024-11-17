BIN=dns-monitor 
CFLAGS= -std=gnu99 -Wall -Werror -Wextra -pedantic -g
LDFLAGS= -lpcap
CC=gcc
B=build
SRC=src
OBJS= $(B)/dns_monitor.o $(B)/arg_parser.o $(B)/dns_parser.o $(B)/linked_list.o

# Executable target
$(BIN): $(OBJS)
	@echo "Linking objects to executable"
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

# Object dns_monitor.o
$(B)/dns_monitor.o: $(SRC)/dns_monitor.c
	@mkdir -p build
	@echo "Compiling dns_monitor.o"
	$(CC) $(CFLAGS) -c $(SRC)/dns_monitor.c -o $@

# Object arg_parser.o
$(B)/arg_parser.o: $(SRC)/arg_parser.c $(SRC)/dns_monitor.h
	@mkdir -p build
	@echo "Compiling arg_parser.o"
	$(CC) $(CFLAGS) -c $(SRC)/arg_parser.c -o $@

$(B)/dns_parser.o: $(SRC)/dns_parser.c $(SRC)/dns_monitor.h
	@mkdir -p build
	@echo "Compiling dns_parser.o"
	$(CC) $(CFLAGS) -c $(SRC)/dns_parser.c -o $@

$(B)/linked_list.o: $(SRC)/linked_list.c $(SRC)/linked_list.h
	@mkdir -p build
	@echo "Compiling linked_list.o"
	$(CC) $(CFLAGS) -c $(SRC)/linked_list.c -o $@

# Test object files (excluding main)
TEST_OBJS = $(B)/arg_parser.o $(B)/dns_parser.o $(B)/linked_list.o

test: $(TEST_OBJS) tests/test_main.c
	@mkdir -p build
	@echo "Compiling test_main.o"
	$(CC) $(CFLAGS) -c tests/test_main.c -o $(B)/test_main.o
	@echo "Linking objects to executable"
	$(CC) $(CFLAGS) $(TEST_OBJS) $(B)/test_main.o -o test -lcunit $(LDFLAGS)
	@echo "Running tests"
	./test

# Clean target
.PHONY: clean
clean:
	rm -rf $(B) $(BIN)
	rm -f domain.txt
	rm -f translation.txt
