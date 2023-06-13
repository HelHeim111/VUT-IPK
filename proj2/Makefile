NAME = sniffer
TARGET = ipk-sniffer
LDFLAGS=-lpcap
CC = g++

all: $(NAME).cpp
	$(CC) -o $(TARGET) $(NAME).cpp $(LDFLAGS)

clean:
	rm $(TARGET)
