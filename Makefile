BIN=dns-monitor 
CFLAGS= -std=gnu99 -Wall -Wextra -Werror -pedantic -g
CC=gcc
B=build
SRC=src
OBJS= $(B)/main.o $(B)/utility.o

# Executable target
$(BIN): $(OBJS)
	@echo "Linking objects to executable"
	$(CC) $(CFLAGS) $(OBJS) -o $@

# Object main.o
$(B)/main.o: $(SRC)/main.c
	@mkdir -p build
	@echo "Compiling main.o"
	$(CC) $(CFLAGS) -c $< -o $@

# Object supp.o
$(B)/utility.o: $(SRC)/utility.c $(SRC)/utility.h
	@mkdir -p build
	@echo "Compiling utility.o"
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
.PHONY: clean
clean:
	rm -rf $(B) $(BIN)
