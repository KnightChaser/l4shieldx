CC = gcc
CFLAGS = -Wall -Wextra -O2
SRCDIR = src
OBJ = main.o connection.o
TARGET = flooder

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

main.o: $(SRCDIR)/main.c $(SRCDIR)/connection.h
	$(CC) $(CFLAGS) -c $< -o $@

connection.o: $(SRCDIR)/connection.c $(SRCDIR)/connection.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
