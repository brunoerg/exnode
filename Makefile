# Builds native code against the pinned Bitcoin Core v32.1 in vendor/bitcoin.
CORE_DIR ?= $(CURDIR)/vendor/bitcoin
KERNEL_INC := $(CORE_DIR)/src/kernel
KERNEL_LIB := $(CORE_DIR)/build-kernel/lib
ERTS_INCLUDE_DIR ?= $(shell erl -noshell -eval 'io:format("~ts/erts-~ts/include", [code:root_dir(), erlang:system_info(version)]), halt().')
PRIV := $(CURDIR)/priv/native

CFLAGS ?= -O2 -Wall -Wextra -Werror
NIF_CFLAGS := $(CFLAGS) -fPIC -std=c11 -I$(ERTS_INCLUDE_DIR) -I$(KERNEL_INC)
NIF_LDFLAGS := -shared -L$(KERNEL_LIB) -lbitcoinkernel -Wl,-rpath,$(KERNEL_LIB)

SECP_INC := $(CORE_DIR)/src/secp256k1/include
SECP_LIB := $(CORE_DIR)/build-kernel/src/secp256k1/lib/libsecp256k1.a

all: $(PRIV)/kernel_nif.so $(PRIV)/shadow_validator $(PRIV)/secp_nif.so

# ElligatorSwift for BIP324: the libsecp256k1 built with the pinned Core.
$(PRIV)/secp_nif.so: native/secp_nif/secp_nif.c $(SECP_LIB)
	@mkdir -p $(PRIV)
	$(CC) $(CFLAGS) -fPIC -std=c11 -D_DEFAULT_SOURCE -I$(ERTS_INCLUDE_DIR) -I$(SECP_INC) $< -o $@ -shared $(SECP_LIB)

$(PRIV)/kernel_nif.so: native/kernel_nif/kernel_nif.c $(KERNEL_INC)/bitcoinkernel.h
	@mkdir -p $(PRIV)
	$(CC) $(NIF_CFLAGS) $< -o $@ $(NIF_LDFLAGS)

$(PRIV)/shadow_validator: native/shadow_validator/shadow_validator.c $(KERNEL_INC)/bitcoinkernel.h
	@mkdir -p $(PRIV)
	$(CC) $(CFLAGS) -std=c11 -D_POSIX_C_SOURCE=200809L -I$(KERNEL_INC) $< -o $@ -L$(KERNEL_LIB) -lbitcoinkernel -Wl,-rpath,$(KERNEL_LIB)

compile_flags.txt:
	printf -- '-std=c11\n-I$(ERTS_INCLUDE_DIR)\n-I$(KERNEL_INC)\n' > $@

clean:
	rm -rf $(PRIV)

.PHONY: all clean
