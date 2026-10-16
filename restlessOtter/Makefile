CC ?= clang
TARGET = restlessOtter
SRC = restlessotter.c

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
PLATFORM_FLAGS = -mmacosx-version-min=10.13
STRIP_CMD = strip $(TARGET)
else
PLATFORM_FLAGS =
STRIP_CMD = strip $(TARGET)
endif

CFLAGS_RELEASE = -O2 -Wall -Wextra -std=c11 $(PLATFORM_FLAGS)
CFLAGS_DEBUG = -O0 -g -Wall -Wextra -std=c11 $(PLATFORM_FLAGS)

.PHONY: all release debug clean strings-check

all: release

release: $(SRC)
	$(CC) $(CFLAGS_RELEASE) -o $(TARGET) $(SRC)
	$(STRIP_CMD) || true

debug: $(SRC)
	$(CC) $(CFLAGS_DEBUG) -o $(TARGET)_debug $(SRC)

strings-check: release
	@strings $(TARGET) | grep -E 'github|example\.com|ticket|RO\{|operation|decoded|phoning|User-Agent' && exit 1 || true

clean:
	rm -f $(TARGET) $(TARGET)_debug
