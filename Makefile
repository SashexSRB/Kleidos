# Compiler and tools
CXX = g++
CFLAGS = -std=c++26 -O2 -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -Wl,-z,relro,-z,now -lpthread -ldl -lsodium -lcrypto -lssl
TARGET = kleidos
SRC = $(wildcard *.cpp)

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean: 
	rm -f $(TARGET)

.PHONY: all clean
