MONOCYPHERLIB=monocypher

CFLAGS +=-DCRYPTO_MONOCYPHER
CRYPTOSRC +=$(SRC_DIR)/crypt/helpers.c
CRYPTOSRC +=$(SRC_DIR)/crypt/monocypher.c

MONOCYPHER_DIR ?= ../Monocypher/

ifeq ($(MONOCYPHER_LOCAL), 1)
  MONOCYPHER_INCLUDE ?= -I$(MONOCYPHER_DIR)/src
  MONOCYPHER_LIB ?= $(MONOCYPHER_DIR)/lib/libmonocypher.so
else
  MONOCYPHER_INCLUDE ?= $(shell pkg-config --cflags $(MONOCYPHERLIB))
  MONOCYPHER_LIB ?= $(shell pkg-config --libs $(MONOCYPHERLIB))
endif

CFLAGS_CRYPTO += $(MONOCYPHER_INCLUDE)
LDFLAGS_CRYPTO += -Wl,$(MONOCYPHER_LIB)
