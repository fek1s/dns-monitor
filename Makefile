BIN=dns-monitor 
CFLAGS= -std=gnu99 -Wall -Wextra -Werror -pedantic -g
LDFLAGS= -lpcap
CC=gcc
B=build
SRC=src
OBJS= $(B)/dns_monitor.o $(B)/arg_parser.o

# Executable target
$(BIN): $(OBJS)
	@echo "Linking objects to executable"
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

# Object dns_monitor.o
$(B)/dns_monitor.o: $(SRC)/dns_monitor.c
	@mkdir -p build
	@echo "Compiling dns_monitor.o"
	$(CC) $(CFLAGS) -c $< -o $@

# Object arg_parser.o
$(B)/arg_parser.o: $(SRC)/arg_parser.c $(SRC)/dns_monitor.h
	@mkdir -p build
	@echo "Compiling arg_parser.o"
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
.PHONY: clean
clean:
	rm -rf $(B) $(BIN)
