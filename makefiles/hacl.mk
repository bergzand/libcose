HACL_DIR ?= ../hacl-c
CFLAGS+=-DCRYPTO_HACL
HACLLIB=hacl
CRYPTOSRC += $(SRC_DIR)/crypt/hacl.c
CRYPTOSRC += $(SRC_DIR)/crypt/helpers.c
CFLAGS_CRYPTO += -I$(HACL_DIR)
LDFLAGS_CRYPTO += -Wl,$(HACL_DIR)/libhacl.so
