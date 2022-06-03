CFLAGS += -Wno-sign-compare
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-char-subscripts
CFLAGS += -Wno-shadow

HASH_SIGS_DIR ?= $(PWD)/../hash-sigs
CFLAGS+=-DCRYPTO_HASH_SIGS -I$(HASH_SIGS_DIR)

CRYPTOSRC +=$(SRC_DIR)/crypt/hash-sigs.c

CRYPTOSRC+=$(HASH_SIGS_DIR)/hss.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_alloc.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_aux.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_common.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_compute.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_generate.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_keygen.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_param.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_reserve.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_sign.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_sign_inc.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_verify.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_verify_inc.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_derive.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_zeroize.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hss_thread_single.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/lm_common.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/lm_ots_common.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/lm_ots_sign.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/lm_ots_verify.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/lm_verify.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/endian.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/hash.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/sha256.c
CRYPTOSRC+=$(HASH_SIGS_DIR)/signatures.c
CRYPTOSRC+=$(SRC_DIR)/crypt/helpers.c
CRYPTOOBJS+=$(CRYPTOSRC:.c:.c)
