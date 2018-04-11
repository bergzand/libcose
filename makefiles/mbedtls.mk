MBEDTLS_LIB ?= "/usr/lib64/libmbedcrypto.so"

CFLAGS+=-DCRYPTO_MBEDTLS
CRYPTOSRC=$(SRC_DIR)/crypt/mbedtls.c

LDFLAGS_CRYPTO += -Wl,$(MBEDTLS_LIB)
