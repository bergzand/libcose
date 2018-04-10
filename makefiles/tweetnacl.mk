CFLAGS+=-DCRYPTO_TWEETNACL -I../tweetnacl
CRYPTOLIB=tweetnacl
NACLSRC=../tweetnacl/tweetnacl.c
CRYPTOSRC+=$(NACLSRC)
CRYPTOSRC+=$(SRC_DIR)/crypt/helpers.c
CRYPTOSRC+=$(SRC_DIR)/crypt/tweetnacl.c
