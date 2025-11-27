ARG BUILD_REGISTRY=

FROM debian:trixie-slim AS build-stage

COPY ci/dpkg.cfg.d/excludes /etc/dpkg/dpkg.cfg.d/excludes
# This is not the runtime/final image:
#   * we keep some installation steps in different layers to improve cachability
#   * this only covers build deps
RUN apt-get update && \
  apt-get install -y \
    build-essential \
    autoconf \
    automake \
    bash \
    bison \
    cmake \
    default-libmysqlclient-dev \
    libnuma-dev \
    flex \
    gcc \
    g++ \
    git \
    libcurl4-openssl-dev \
    libjansson-dev \
    libjson-c-dev \
    libnetfilter-log-dev \
    libpcap-dev \
    libpq-dev \
    libsnappy-dev \
    libzstd-dev \
    libsqlite3-dev \
    libssl-dev \
    libgnutls28-dev \
    libnsl-dev \
    libtool \
    make \
    pkg-config \
    sudo \
    wget \
    zlib1g-dev

WORKDIR /tmp/pmacct/
# About to deal with deps installation
COPY ci/deps.sh ci/
# Parallelism: 2 looks a reasonable default, and bear in mind CI specs
ARG NUM_WORKERS=2
ENV MAKEFLAGS="-j${NUM_WORKERS}"
# Do not check certificates in wget for external deps
ARG DEPS_DONT_CHECK_CERTIFICATE
RUN ./ci/deps.sh


# Actual build
COPY . .
RUN export AVRO_LIBS="-L/usr/local/avro/lib -lavro" && \
  export AVRO_CFLAGS="-I/usr/local/avro/include" && \
  ./autogen.sh && ./configure --enable-mysql --enable-pgsql     \
                              --enable-sqlite3 --enable-kafka   \
                              --enable-geoipv2 --enable-jansson \
                              --enable-rabbitmq --enable-nflog  \
                              --enable-ndpi --enable-zmq        \
                              --enable-avro --enable-serdes     \
                              --enable-redis --enable-gnutls    \
                              --enable-unyte-udp-notif &&       \
  make install

RUN apt-get update && apt-get install -y curl rustup clang

WORKDIR /tmp/pmacct/src/external_libs/libcdada/

RUN autoreconf -fi && ./configure && make install && make clean

RUN ldconfig

RUN rustup toolchain install nightly

RUN rustup default nightly

RUN cargo install --git https://github.com/network-analytics/cargo-c cargo-c

WORKDIR /usr/pmacct-gauze
COPY docker/pmacct-gauze/ .

RUN cargo clean

RUN PMACCT_INCLUDE_DIR="/tmp" cargo cinstall -vv --package pmacct-gauze-lib
RUN ldconfig

WORKDIR /usr/pmacct-gauze/poc_gauze_lib

RUN autoreconf -fi

RUN ./configure

RUN PMACCT_INCLUDE_DIR="/tmp/pmacct/" make


CMD ["/bin/bash"]

# COPY --from=0 /tmp/pmacct-gauze/poc_gauze_lib/src/.libs/libparse.so /