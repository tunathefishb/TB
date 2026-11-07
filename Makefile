CC           ?= gcc
TLS          ?= builtin

CFLAGS       ?= -std=c11 -O2 -Wall -Wextra
LDFLAGS      ?=

BUILD_DIR    := build

INC_DIRS     := -Isrc/core -Isrc/net -Isrc/tls -Isrc/js -Isrc/engine -Isrc/ui -Itests

MODE_CFLAGS  := $(INC_DIRS) -D_GNU_SOURCE
MODE_LDFLAGS := -lm

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

TEST_SRCS := \
	tests/test_main.c \
	tests/test_core.c \
	tests/test_engine.c \
	tests/test_js.c \
	tests/test_net.c \
	tests/test_tls.c

vpath %.c src/core src/net src/tls src/js src/engine src/ui tests

CORE_OBJS    := $(addprefix $(BUILD_DIR)/,$(notdir $(CORE_SRCS:.c=.o)))
MAIN_OBJ     := $(BUILD_DIR)/main.o
TEST_OBJS    := $(addprefix $(BUILD_DIR)/,$(notdir $(TEST_SRCS:.c=.o)))
HEADERS      := $(wildcard src/*/*.h tests/*.h)

CONFIG_STR   := TLS=$(TLS)
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

$(BUILD_DIR)/test_suite: $(CORE_OBJS) $(TEST_OBJS) $(CONFIG_STAMP)
	$(CC) $(ALL_CFLAGS) -o $@ $(CORE_OBJS) $(TEST_OBJS) $(ALL_LDFLAGS)

test: $(BUILD_DIR)/test_suite
	./$(BUILD_DIR)/test_suite $(FILTER)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) tb
