CBOR_ROOT ?= $(PWD)/../cn-cbor/
TINYCBOR_ROOT ?= $(PWD)/../tinycbor/
NANOCBOR_ROOT ?= $(PWD)/../nanocbor/
INC_GLOBAL ?= /usr/include
CRYPTO ?= sodium

CC ?= gcc
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

INC_TINYCBOR=$(TINYCBOR_ROOT)/src
LIB_TINYCBOR_PATH=$(TINYCBOR_ROOT)/lib
LIB_TINYCBOR=$(LIB_TINYCBOR_PATH)/libtinycbor.so

INC_NANOCBOR=$(NANOCBOR_ROOT)/include
LIB_NANOCBOR_PATH=$(NANOCBOR_ROOT)/bin
LIB_NANOCBOR=$(LIB_NANOCBOR_PATH)/nanocbor.so

CFLAGS_TIDY ?= -std=c99
TIDYFLAGS=-checks=* -warnings-as-errors=*

CFLAGS_COVERAGE += -coverage
CFLAGS_DEBUG += $(CFLAGS_COVERAGE) -g3

CFLAGS_WARN += -Wall -Wextra -pedantic -Werror -Wshadow
CFLAGS += -fPIC $(CFLAGS_WARN) -I$(INC_DIR) -I$(INC_GLOBAL) -I$(INC_TINYCBOR) -I$(INC_NANOCBOR) -Os -g3

ifneq (,$(filter sodium,$(CRYPTO)))
	include $(MK_DIR)/sodium.mk
endif
ifneq (,$(filter monocypher,$(CRYPTO)))
	include $(MK_DIR)/monocypher.mk
endif
ifneq (,$(filter mbedtls,$(CRYPTO)))
	include $(MK_DIR)/mbedtls.mk
endif
ifneq (,$(filter hacl,$(CRYPTO)))
	include $(MK_DIR)/hacl.mk
endif
ifneq (,$(filter c25519,$(CRYPTO)))
	include $(MK_DIR)/c25519.mk
endif

CFLAGS += $(CFLAGS_CRYPTO)

SRCS+=$(wildcard $(SRC_DIR)/*.c)
BUILDSRCS=$(SRCS) $(CRYPTOSRC)
TIDYSRCS=$(SRCS)
TESTS+=$(wildcard $(TEST_DIR)/*.c)

OBJS=$(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(BUILDSRCS))
OTESTS=$(patsubst %.c,$(OBJ_DIR)/%.o,$(TESTS))

OBJS += $(CRYPTOOBJS)

CFLAGS_TEST += $(shell pkg-config --cflags cunit) $(CFLAGS_COVERAGE)
LDFLAGS_TEST += -Wl,$(shell pkg-config --libs cunit || echo -lcunit) -Wl,$(LIB_TINYCBOR)

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
	$(CC) $(CFLAGS) $(OBJS) $(OTESTS) -o $@  -Wl,$(LIB_TINYCBOR) -Wl,$(LIB_NANOCBOR) $(LDFLAGS)

$(BIN_DIR)/libcose.so: $(OBJS) prepare
	$(CC) $(CFLAGS) $(OBJS) -o $@ -Wl,$(LIB_NANOCBOR)  -shared

test: $(BIN_DIR)/test
	LD_LIBRARY_PATH=$(LIB_TINYCBOR_PATH) $<

debug-test: CFLAGS += $(CFLAGS_DEBUG)
debug-test: $(BIN_DIR)/test
	LD_LIBRARY_PATH=$(LIB_TINYCBOR_PATH) gdb $<

clang-tidy:
	$(TIDY) $(TIDYFLAGS) $(TIDYSRCS) -- $(CFLAGS) $(CFLAGS_TIDY)

clean:
	$(RM) $(BIN_DIR)

print-%:
	@echo $* = $($*)

.PHONY: prepare clean test debug-test lib clang-tidy
.SECONDARY: ${OBJS} ${OTESTS}
