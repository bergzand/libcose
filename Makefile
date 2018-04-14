CBOR_ROOT ?= $(PWD)/../cn-cbor/
INC_GLOBAL ?= /usr/include
CRYPTO ?= sodium

CC=gcc
RM=rm -rf
TIDY=clang-tidy

INC_DIR=include
SRC_DIR=src
TEST_DIR=tests
BIN_DIR=bin
MK_DIR=makefiles
OBJ_DIR=$(BIN_DIR)/objs

LIB_DIR=lib
BUILD_DIR=$(PWD)

INC_CBOR=$(CBOR_ROOT)/include
LIB_CBOR_PATH=$(CBOR_ROOT)/build/dist/lib
LIB_CBOR=$(LIB_CBOR_PATH)/libcn-cbor.so

TIDYFLAGS=-checks=* -warnings-as-errors=*

CFLAGS_COVERAGE += -coverage 
CFLAGS_DEBUG += $(CFLAGS_COVERAGE) -g3


CFLAGS_WARN += -Wall -Wextra -pedantic -Werror -Wshadow
CFLAGS += -fPIC $(CFLAGS_WARN) -I$(INC_DIR) -I$(INC_GLOBAL) -I$(INC_CBOR) -std=c99
CFLAGS +=-DUSE_CBOR_CONTEXT

ifeq ($(CRYPTO), sodium)
	include $(MK_DIR)/sodium.mk
endif
ifeq ($(CRYPTO), mbedtls)
	include $(MK_DIR)/mbedtls.mk
endif
ifeq ($(CRYPTO), tweetnacl)
	include $(MK_DIR)/tweetnacl.mk
endif

SRCS+=$(wildcard $(SRC_DIR)/*.c)
BUILDSRCS=$(SRCS) $(CRYPTOSRC)
TIDYSRCS=$(SRCS) 
TESTS+=$(wildcard $(TEST_DIR)/*.c)

OBJS=$(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(BUILDSRCS))
OTESTS=$(patsubst %.c,$(OBJ_DIR)/%.o,$(TESTS))

CFLAGS_TEST += $(shell pkg-config --cflags cunit) $(CFLAGS_COVERAGE)
LDFLAGS_TEST += -Wl,$(shell pkg-config --libs cunit || echo -lcunit)

LDFLAGS += $(LDFLAGS_CRYPTO)

lib: $(BIN_DIR)/libcose.so

prepare:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(OBJ_DIR)/crypt
	@mkdir -p $(OBJ_DIR)/tests

# Build a binary
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/tests/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_DIR)/test: CFLAGS += $(CFLAGS_TEST)
$(BIN_DIR)/test: LDFLAGS += $(LDFLAGS_TEST)
$(BIN_DIR)/test: $(OBJS) $(OTESTS) prepare
	$(CC) $(CFLAGS) $(OBJS) $(OTESTS) -o $@ -Wl,$(LIB_CBOR) $(LDFLAGS)

$(BIN_DIR)/libcose.so: $(OBJS) prepare
	$(CC) $(CFLAGS) $(OBJS) -o $@ -Wl,$(LIB_CBOR) -shared

test: $(BIN_DIR)/test
	LD_LIBRARY_PATH=$(LIB_CBOR_PATH) $<

debug-test: CFLAGS += $(CFLAGS_DEBUG)
debug-test: $(BIN_DIR)/test
	LD_LIBRARY_PATH=$(LIB_CBOR_PATH) gdb $<

clang-tidy:
	$(TIDY) $(TIDYFLAGS) $(TIDYSRCS) -- $(CFLAGS)

clean:
	$(RM) $(BIN_DIR)

print-%:
	@echo $* = $($*)

.PHONY: prepare clean test debug-test lib clang-tidy
.SECONDARY: ${OBJS} ${OTESTS}
