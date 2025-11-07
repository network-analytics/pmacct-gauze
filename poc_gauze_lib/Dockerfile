ARG BUILD_REGISTRY=

FROM ${BUILD_REGISTRY:+${BUILD_REGISTRY}/}pmacct-build-image AS build-stage



RUN apt-get update && apt-get install -y \
    curl \
    rustup \
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
    zlib1g-dev \
    clang

WORKDIR /tmp/pmacct/src/external_libs/libcdada/

RUN autoreconf -fi && ./configure && make install && make clean

RUN ldconfig

RUN rustup toolchain install nightly

RUN rustup default nightly

RUN cargo install --git https://github.com/network-analytics/cargo-c cargo-c

WORKDIR /tmp/pmacct-gauze
COPY . .

RUN cargo clean

RUN PMACCT_INCLUDE_DIR="/tmp" cargo cinstall -vv --package pmacct-gauze-lib
RUN ldconfig

WORKDIR /tmp/pmacct-gauze/poc_gauze_lib

RUN autoreconf -fi

RUN ./configure

RUN PMACCT_INCLUDE_DIR="/tmp/pmacct/src" make

# COPY --from=0 /tmp/pmacct-gauze/poc_gauze_lib/src/.libs/libparse.so /