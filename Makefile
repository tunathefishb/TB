CC           ?= gcc
FREESTANDING ?= 1
TLS          ?= builtin

CFLAGS       ?= -std=c11 -O2 -Wall -Wextra
LDFLAGS      ?=

BUILD_DIR    := build

MODE_CFLAGS  :=
MODE_LDFLAGS :=

ifeq ($(FREESTANDING),1)
ifeq ($(TLS),openssl)
$(error TLS=openssl requires FREESTANDING=0 (dlopen/libssl needs dynamic libc loader))
endif
MODE_CFLAGS  += -DTB_FREESTANDING=1 -ffreestanding -fno-stack-protector -fno-pie
MODE_LDFLAGS += -nostdlib -static -no-pie
else
MODE_CFLAGS  += -DTB_FREESTANDING=0 -D_GNU_SOURCE
endif

ifeq ($(TLS),openssl)
MODE_CFLAGS  += -DTB_TLS_OPENSSL=1
MODE_LDFLAGS += -ldl
TLS_SRCS     :=
else ifeq ($(TLS),builtin)
MODE_CFLAGS  += -DTB_TLS_OPENSSL=0
TLS_SRCS     := src/tls_crypto.c src/tls_x509.c src/tls.c
else
$(error Unknown TLS=$(TLS); expected 'builtin' or 'openssl')
endif

ALL_CFLAGS   := $(CFLAGS) $(MODE_CFLAGS)
ALL_LDFLAGS  := $(LDFLAGS) $(MODE_LDFLAGS)

CORE_SRCS := \
	src/sys.c \
	src/math_tb.c \
	src/regex_tb.c \
	src/mem.c \
	src/inflate.c \
	src/net.c \
	src/dom.c \
	src/css.c \
	src/js_parse.c \
	src/js_gc.c \
	src/js_stdlib.c \
	src/js_eval.c \
	src/js_dom.c \
	src/layout.c \
	src/browser.c \
	src/tui.c \
	$(TLS_SRCS)

CORE_OBJS    := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(CORE_SRCS))
MAIN_OBJ     := $(BUILD_DIR)/main.o
TEST_OBJ     := $(BUILD_DIR)/test_suite.o
HEADERS      := $(wildcard src/*.h)

CONFIG_STR   := FREESTANDING=$(FREESTANDING) TLS=$(TLS)
CONFIG_STAMP := $(BUILD_DIR)/.config

.PHONY: all test clean FORCE

all: tb

$(CONFIG_STAMP): FORCE | $(BUILD_DIR)
	@if [ ! -f $@ ] || [ "$$(cat $@)" != "$(CONFIG_STR)" ]; then \
		echo "$(CONFIG_STR)" > $@; \
	fi

tb: $(CORE_OBJS) $(MAIN_OBJ) $(CONFIG_STAMP)
	$(CC) $(ALL_CFLAGS) -o $@ $(CORE_OBJS) $(MAIN_OBJ) $(ALL_LDFLAGS)

$(BUILD_DIR)/%.o: src/%.c $(HEADERS) $(CONFIG_STAMP) | $(BUILD_DIR)
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

$(TEST_OBJ): tests/test_suite.c $(HEADERS) $(CONFIG_STAMP) | $(BUILD_DIR)
	$(CC) $(ALL_CFLAGS) -Isrc -c -o $@ $<

$(BUILD_DIR)/test_suite: $(CORE_OBJS) $(TEST_OBJ) $(CONFIG_STAMP)
	$(CC) $(ALL_CFLAGS) -o $@ $(CORE_OBJS) $(TEST_OBJ) $(ALL_LDFLAGS)

test: $(BUILD_DIR)/test_suite
	./$(BUILD_DIR)/test_suite

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) tb
