BIN=dns-monitor 
CFLAGS= -std=gnu99 -Wall -Wextra -Werror -pedantic -g
LDFLAGS= -lpcap
CC=gcc
B=build
SRC=src
OBJS= $(B)/main.o $(B)/arg_parser.o

# Executable target
$(BIN): $(OBJS)
	@echo "Linking objects to executable"
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

# Object main.o
$(B)/main.o: $(SRC)/main.c
	@mkdir -p build
	@echo "Compiling main.o"
	$(CC) $(CFLAGS) -c $< -o $@

# Object arg_parser.o
$(B)/arg_parser.o: $(SRC)/arg_parser.c $(SRC)/arg_parser.h
	@mkdir -p build
	@echo "Compiling arg_parser.o"
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
.PHONY: clean
clean:
	rm -rf $(B) $(BIN)
