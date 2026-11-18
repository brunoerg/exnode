# Reproducible release build: contrib/release/build.sh runs it and README
# "Reproducible release" explains it. Every input is pinned: the base image by
# digest, Debian packages by snapshot date, and each download by hash. The
# build runs under fixed paths (/src, /build, /opt) with SOURCE_DATE_EPOCH set
# from the commit, so its output does not depend on the machine, the checkout
# path or the time of the build.
#
# Updating a pin: change the version and its hash together; the build fails
# on a hash mismatch.

# debian:bookworm-slim (glibc 2.36: the release also runs on newer systems).
ARG BASE_IMAGE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

FROM ${BASE_IMAGE} AS toolchain

# snapshot.debian.org serves the archive as it was at this time, so the
# packages (compiler, CMake, Boost, OpenSSL) do not change between builds.
ARG DEBIAN_SNAPSHOT=20261115T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf '%s\n' \
      "deb http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
      "deb http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm-updates main" \
      "deb http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
      > /etc/apt/sources.list && \
    apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=5 update && \
    apt-get install -y --no-install-recommends \
      build-essential ca-certificates cmake libboost-dev liblz4-dev libssl-dev perl pkg-config && \
    rm -rf /var/lib/apt/lists/*

ENV LANG=C.UTF-8

# Erlang/OTP (.tool-versions). OpenSSL is linked into crypto statically and
# termcap is left out, so the release needs neither at runtime.
# --enable-deterministic-build: OTP's own code without absolute paths.
ARG OTP_VERSION=28.5.0.8
ADD --checksum=sha256:8a696e15bcbe5d57197b1f4c03c92d415f9fd9af70f9222a05911c8a5463cba6 \
    https://github.com/erlang/otp/releases/download/OTP-${OTP_VERSION}/otp_src_${OTP_VERSION}.tar.gz /tmp/otp.tar.gz
RUN mkdir /tmp/otp && tar xzf /tmp/otp.tar.gz -C /tmp/otp --strip-components=1 && \
    cd /tmp/otp && \
    ./configure --prefix=/opt/otp --enable-deterministic-build \
      --without-termcap --disable-dynamic-ssl-lib \
      --without-javac --without-jinterface --without-wx --without-odbc \
      --without-observer --without-debugger --without-et --without-megaco && \
    make -j"$(nproc)" && make install && \
    rm -rf /tmp/otp /tmp/otp.tar.gz
# From here on, the rest of the Erlang code (Elixir, rebar3 deps) too. Not
# set for OTP's build: it also strips the paths from `erlc -M`, whose
# dependency files OTP's makefiles need.
ENV PATH=/opt/otp/bin:$PATH \
    ERL_COMPILER_OPTIONS=deterministic

# Elixir (.tool-versions).
ARG ELIXIR_VERSION=1.19.7
ADD --checksum=sha256:a8fa0829edab5fba1394df18b2db884532be320697e2f5bd8cdf78bd9af417b3 \
    https://github.com/elixir-lang/elixir/archive/refs/tags/v${ELIXIR_VERSION}.tar.gz /tmp/elixir.tar.gz
# System.build_info/0 records the build date: a fixed one (any; this is
# 2026-01-01), not the commit's, so the toolchain stays cached across commits.
RUN mkdir /opt/elixir && tar xzf /tmp/elixir.tar.gz -C /opt/elixir --strip-components=1 && \
    SOURCE_DATE_EPOCH=1767225600 make -C /opt/elixir compile && rm /tmp/elixir.tar.gz
ENV PATH=/opt/elixir/bin:$PATH

# Hex and rebar3, which `mix local.hex` / `mix local.rebar` would otherwise
# fetch at their latest versions.
ADD --checksum=sha256:42987665746213c9ec2da00c9c6533641807631f85bc17f3f622bdb1e6a1cdf5 \
    https://builds.hex.pm/installs/1.19.0/hex-2.7.0-otp-28.ez /tmp/hex.ez
ADD --checksum=sha256:58db4c47476c9ba39e668c7fb0b3121381971e38397409956a4a60e1a0152082 \
    https://builds.hex.pm/installs/1.18.4/rebar3-3.28.0-otp-28 /tmp/rebar3
RUN mix archive.install /tmp/hex.ez --force && \
    mix local.rebar rebar3 /tmp/rebar3 --force && \
    rm /tmp/hex.ez /tmp/rebar3

# Bitcoin Core's kernel library, from the release tarball (hash as in
# https://bitcoincore.org/bin/bitcoin-core-32.1/SHA256SUMS).
FROM toolchain AS core
ADD --checksum=sha256:a5f2f61e32cf7f790641c9ec306a3c88ca7b5a556946956b1f35ffd7e27813f9 \
    https://bitcoincore.org/bin/bitcoin-core-32.1/bitcoin-32.1.tar.gz /tmp/core.tar.gz
RUN mkdir -p /src/bitcoin && tar xzf /tmp/core.tar.gz -C /src/bitcoin --strip-components=1 && \
    rm /tmp/core.tar.gz && cd /src/bitcoin && \
    cmake -B build-kernel -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_KERNEL_LIB=ON -DBUILD_SHARED_LIBS=ON \
      -DBUILD_DAEMON=OFF -DBUILD_CLI=OFF -DBUILD_TESTS=OFF -DENABLE_WALLET=OFF -DENABLE_IPC=OFF && \
    cmake --build build-kernel -j"$(nproc)"

FROM core AS build
# SOURCE_DATE_EPOCH: the commit time (build.sh), for every time stamp the
# build writes. ERLANG_ROCKSDB_OPTS: RocksDB with LZ4 (Debian's liblz4: the
# Hex package's bundled copy lacks its build files), without Snappy or zstd,
# stated rather than probed (mix.exs probes for liburing only when it is
# unset), and with OpenSSL linked in as in OTP's crypto. BUNDLE_KERNEL: see
# the Makefile.
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    MIX_ENV=prod \
    CORE_DIR=/src/bitcoin \
    BUNDLE_KERNEL=1 \
    ERLANG_ROCKSDB_OPTS="-DWITH_ZSTD=OFF -DWITH_LZ4=ON -DWITH_SNAPPY=OFF -DOPENSSL_USE_STATIC_LIBS=TRUE"
WORKDIR /build
COPY mix.exs mix.lock ./
RUN test -n "$SOURCE_DATE_EPOCH" && mix deps.get --only prod && mix deps.compile
COPY Makefile ./
COPY native native
COPY lib lib
COPY rel rel
RUN mix compile && mix release

# One tarball, entries sorted, owned by root, dated at the commit, modes
# without group/other write (the checkout's umask varies), gzip without a
# name or time stamp.
RUN arch="$(uname -m)" && vsn="$(cut -d' ' -f2 _build/prod/rel/exnode/releases/start_erl.data)" && \
    name="exnode-${vsn}-${arch}-linux-gnu" && \
    mkdir /out && \
    tar -C _build/prod/rel --transform "s,^exnode,${name}," \
      --sort=name --format=gnu --owner=0 --group=0 --numeric-owner \
      --mtime="@${SOURCE_DATE_EPOCH}" --mode='u+w,go=u-w' \
      -cf - exnode | gzip -9 -n > "/out/${name}.tar.gz" && \
    cd /out && sha256sum "${name}.tar.gz" > SHA256SUMS

FROM scratch
COPY --from=build /out/ /
