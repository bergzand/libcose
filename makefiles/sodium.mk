CFLAGS += -DCRYPTO_SODIUM
SODIUM_LIB = libsodium
CRYPTOSRC += $(SRC_DIR)/crypt/sodium.c
CFLAGS_CRYPTO += $(shell pkg-config --cflags $(SODIUM_LIB))
LDFLAGS_CRYPTO += -Wl,$(shell pkg-config --libs $(SODIUM_LIB))
