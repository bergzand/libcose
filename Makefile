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
OBJ_DIR=$(BIN_DIR)/objs

LIB_DIR=lib
BUILD_DIR=$(PWD)

INC_CBOR=$(CBOR_ROOT)/include
LIB_CBOR_PATH=$(CBOR_ROOT)/build/dist/lib
LIB_CBOR=$(LIB_CBOR_PATH)/libcn-cbor.so

TIDYFLAGS=-checks=*,-clang-analyzer-alpha.*

CFLAGS+=-Wall -Wextra -pedantic -I$(INC_DIR) -I$(INC_GLOBAL) -I$(INC_CBOR) -g3 -std=c99
CFLAGS+=-DUSE_CBOR_CONTEXT

ifeq ($(CRYPTO), sodium)
	CRYPTOLIB=libsodium
	CRYPTOSRC=$(SRC_DIR)/crypt/crypt_sodium.c
	CFLAGS+=$(shell pkg-config --libs --cflags $(CRYPTOLIB))
else ($(CRYPTO), tweetnacl)
	CRYPTOLIB=tweetnacl
	CRYPTOSRC=$(SRC_DIR)/crypt/crypt_tweetnacl.c
endif

SRCS+=$(wildcard $(SRC_DIR)/*.c)
SRCS+=$(CRYPTOSRC)
TESTS+=$(wildcard $(TEST_DIR)/*.c)

OBJS=$(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
OTESTS=$(patsubst %.c,$(OBJ_DIR)/%.o,$(TESTS))

CFLAGS+=$(shell pkg-config --libs --cflags cunit)

prepare:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(OBJ_DIR)/crypt
	@mkdir -p $(OBJ_DIR)/tests

# Build a binary
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/tests/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_DIR)/%: $(OBJS) $(OTESTS) prepare
	$(CC) $(CFLAGS) $(OBJS) $(OTESTS) -o $@ -Wl,$(LIB_CBOR)  

test: $(BIN_DIR)/test
	LD_LIBRARY_PATH=$(LIB_CBOR_PATH) $<

debug-test: $(BIN_DIR)/test
	LD_LIBRARY_PATH=$(LIB_CBOR_PATH) gdb $<

clean:
	$(RM) $(BIN_DIR)

print-%:
	@echo $* = $($*)

.PHONY: prepare clean test debug-test
.SECONDARY: ${OBJS} ${OTESTS}
