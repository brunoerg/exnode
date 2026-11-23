# Builds native code against the pinned Bitcoin Core v32.1 in vendor/bitcoin.
CORE_DIR ?= $(CURDIR)/vendor/bitcoin
KERNEL_INC := $(CORE_DIR)/src/kernel
KERNEL_LIB := $(CORE_DIR)/build-kernel/lib
ERTS_INCLUDE_DIR ?= $(shell erl -noshell -eval 'io:format("~ts/erts-~ts/include", [code:root_dir(), erlang:system_info(version)]), halt().')
PRIV := $(CURDIR)/priv/native

CFLAGS ?= -O2 -Wall -Wextra -Werror
# Hardening whatever the toolchain's defaults (some enable none of it),
# kept when CFLAGS is overridden. -U first: some compilers predefine the
# fortify level and a plain -D would be a redefinition (an error with -Werror).
HARDEN_CFLAGS := -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
HARDEN_LDFLAGS := -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
# BUNDLE_KERNEL=1 (release builds): copy libbitcoinkernel into priv/native and
# find it there ($ORIGIN) instead of in the Core checkout, whose absolute path
# would otherwise be written into the binaries.
ifeq ($(BUNDLE_KERNEL),1)
KERNEL_RPATH := $$ORIGIN
# The library under its SONAME, the name the binaries ask the loader for.
KERNEL_SONAME := $(shell objdump -p $(KERNEL_LIB)/libbitcoinkernel.so | awk '/SONAME/ {print $$2}')
KERNEL_BUNDLED := $(PRIV)/$(KERNEL_SONAME)
else
KERNEL_RPATH := $(KERNEL_LIB)
KERNEL_BUNDLED :=
endif

NIF_CFLAGS := $(CFLAGS) $(HARDEN_CFLAGS) -fPIC -std=c11 -I$(ERTS_INCLUDE_DIR) -I$(KERNEL_INC)
NIF_LDFLAGS := -shared $(HARDEN_LDFLAGS) -L$(KERNEL_LIB) -lbitcoinkernel -Wl,-rpath,'$(KERNEL_RPATH)'

SECP_INC := $(CORE_DIR)/src/secp256k1/include
SECP_LIB := $(CORE_DIR)/build-kernel/src/secp256k1/lib/libsecp256k1.a

all: $(PRIV)/kernel_nif.so $(PRIV)/shadow_validator $(PRIV)/secp_nif.so $(PRIV)/sort_nif.so $(PRIV)/overlay_nif.so $(KERNEL_BUNDLED)

# A regular file (cp -L): no symlinks in the release.
ifeq ($(BUNDLE_KERNEL),1)
$(KERNEL_BUNDLED): $(KERNEL_LIB)/libbitcoinkernel.so
	@test -n "$(KERNEL_SONAME)" || { echo "no SONAME in $<" >&2; exit 1; }
	@mkdir -p $(PRIV)
	cp -L $< $@
endif

# ElligatorSwift for BIP324: the libsecp256k1 built with the pinned Core.
$(PRIV)/secp_nif.so: native/secp_nif/secp_nif.c $(SECP_LIB)
	@mkdir -p $(PRIV)
	$(CC) $(CFLAGS) $(HARDEN_CFLAGS) -fPIC -std=c11 -D_DEFAULT_SOURCE -I$(ERTS_INCLUDE_DIR) -I$(SECP_INC) $< -o $@ -shared $(HARDEN_LDFLAGS) $(SECP_LIB)

# Key-ordered packed KV records (Exnode.Store.PackedSort): no libraries.
$(PRIV)/sort_nif.so: native/sort_nif/sort_nif.c
	@mkdir -p $(PRIV)
	$(CC) $(CFLAGS) $(HARDEN_CFLAGS) -fPIC -std=c11 -I$(ERTS_INCLUDE_DIR) $< -o $@ -shared $(HARDEN_LDFLAGS)

# The archive overlay's coin tables (Exnode.Archive.Overlay): no libraries.
$(PRIV)/overlay_nif.so: native/overlay_nif/overlay_nif.c
	@mkdir -p $(PRIV)
	$(CC) $(CFLAGS) $(HARDEN_CFLAGS) -fPIC -std=c11 -D_DEFAULT_SOURCE -I$(ERTS_INCLUDE_DIR) $< -o $@ -shared $(HARDEN_LDFLAGS)

$(PRIV)/kernel_nif.so: native/kernel_nif/kernel_nif.c $(KERNEL_INC)/bitcoinkernel.h
	@mkdir -p $(PRIV)
	$(CC) $(NIF_CFLAGS) $< -o $@ $(NIF_LDFLAGS)

$(PRIV)/shadow_validator: native/shadow_validator/shadow_validator.c $(KERNEL_INC)/bitcoinkernel.h
	@mkdir -p $(PRIV)
	$(CC) $(CFLAGS) $(HARDEN_CFLAGS) -std=c11 -D_POSIX_C_SOURCE=200809L -I$(KERNEL_INC) $< -o $@ $(HARDEN_LDFLAGS) -L$(KERNEL_LIB) -lbitcoinkernel -Wl,-rpath,'$(KERNEL_RPATH)'

compile_flags.txt:
	printf -- '-std=c11\n-I$(ERTS_INCLUDE_DIR)\n-I$(KERNEL_INC)\n' > $@

clean:
	rm -rf $(PRIV)

.PHONY: all clean
