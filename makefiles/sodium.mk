CFLAGS+=-DCRYPTO_SODIUM
CRYPTOLIB=libsodium
CRYPTOSRC=$(SRC_DIR)/crypt/sodium.c
CFLAGS_CRYPTO += $(shell pkg-config --cflags $(CRYPTOLIB))
LDFLAGS_CRYPTO += -Wl,$(shell pkg-config --libs $(CRYPTOLIB))
