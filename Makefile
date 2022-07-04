TARGET := msync_receiver
SOURCE := msync_receiver.c

default: $(TARGET)

CC ?= gcc
WFLAGS ?= -Wall -Wextra -fstack-protector-all -Wstack-protector
CFLAGS ?= -O2 -pipe $(WFLAGS) -pthread -DHAVE_GETIFADDRS
LDFLAGS ?=

$(TARGET): $(SOURCE)
	@echo Building $@
	@$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

.PHONY: clean
clean:
	@rm -f $(TARGET)
