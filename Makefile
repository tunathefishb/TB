CC           ?= gcc
FREESTANDING ?= 1
TLS          ?= builtin

CFLAGS       ?= -std=c11 -O2 -Wall -Wextra
LDFLAGS      ?=

BUILD_DIR    := build

INC_DIRS     := -Isrc/core -Isrc/net -Isrc/tls -Isrc/js -Isrc/engine -Isrc/ui

MODE_CFLAGS  := $(INC_DIRS)
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
TLS_SRCS     := \
	src/tls/tls_sym.c \
	src/tls/tls_asym.c \
	src/tls/tls_x509.c \
	src/tls/tls_conn.c
else
$(error Unknown TLS=$(TLS); expected 'builtin' or 'openssl')
endif

ALL_CFLAGS   := $(CFLAGS) $(MODE_CFLAGS)
ALL_LDFLAGS  := $(LDFLAGS) $(MODE_LDFLAGS)

CORE_SRCS := \
	src/core/sys_syscall.c \
	src/core/sys_stdio.c \
	src/core/sys_stdlib.c \
	src/core/math_tb.c \
	src/core/regex_tb.c \
	src/core/mem.c \
	src/core/inflate.c \
	src/net/url.c \
	src/net/about.c \
	src/net/dns.c \
	src/net/http.c \
	src/engine/dom.c \
	src/engine/css.c \
	src/engine/layout.c \
	src/js/js_parse.c \
	src/js/js_gc.c \
	src/js/js_stdlib.c \
	src/js/js_json.c \
	src/js/js_eval.c \
	src/js/js_dom.c \
	src/ui/browser.c \
	src/ui/tui.c \
	$(TLS_SRCS)

vpath %.c src/core src/net src/tls src/js src/engine src/ui

CORE_OBJS    := $(addprefix $(BUILD_DIR)/,$(notdir $(CORE_SRCS:.c=.o)))
MAIN_OBJ     := $(BUILD_DIR)/main.o
TEST_OBJ     := $(BUILD_DIR)/test_suite.o
HEADERS      := $(wildcard src/*/*.h)

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

$(BUILD_DIR)/%.o: %.c $(HEADERS) $(CONFIG_STAMP) | $(BUILD_DIR)
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

$(TEST_OBJ): tests/test_suite.c $(HEADERS) $(CONFIG_STAMP) | $(BUILD_DIR)
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/test_suite: $(CORE_OBJS) $(TEST_OBJ) $(CONFIG_STAMP)
	$(CC) $(ALL_CFLAGS) -o $@ $(CORE_OBJS) $(TEST_OBJ) $(ALL_LDFLAGS)

test: $(BUILD_DIR)/test_suite
	./$(BUILD_DIR)/test_suite

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) tb
