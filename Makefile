CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = encoder
SOURCE = encoder.c

# Windows平台
ifeq ($(OS),Windows_NT)
	TARGET = encoder.exe
endif

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET) $(TARGET).exe

.PHONY: all clean

