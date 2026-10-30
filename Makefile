CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra
LDFLAGS ?= -lm -ldl

BUILD_DIR := build

CORE_SRCS := \
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
	src/tui.c

CORE_OBJS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(CORE_SRCS))
MAIN_OBJ  := $(BUILD_DIR)/main.o
TEST_OBJ  := $(BUILD_DIR)/test_suite.o

HEADERS := $(wildcard src/*.h)

.PHONY: all test clean

all: tb

tb: $(CORE_OBJS) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: src/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_OBJ): tests/test_suite.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Isrc -c -o $@ $<

$(BUILD_DIR)/test_suite: $(CORE_OBJS) $(TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(BUILD_DIR)/test_suite
	./$(BUILD_DIR)/test_suite

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) tb
