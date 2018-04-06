CFLAGS+=-DCRYPTO_TWEETNACL -I../tweetnacl
CRYPTOLIB=tweetnacl
CRYPTOSRC=../tweetnacl/tweetnacl.c
CRYPTOSRC+=$(SRC_DIR)/crypt/helpers.c
CRYPTOSRC+=$(SRC_DIR)/crypt/tweetnacl.c
