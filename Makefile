# Compiler and tools
CXX = g++
CFLAGS = -std=c++20 -O2 -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -Wl,-z,relro,-z,now -lpthread -ldl -lsodium -lcrypto -lssl
TARGET = kleidos
SRC = $(wildcard *.cpp)
VAULTFILE = vault.kle

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean: 
	rm -f $(TARGET)
	rm -f $(VAULTFILE)

.PHONY: all clean
