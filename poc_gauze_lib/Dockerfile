ARG BUILD_REGISTRY=

FROM ${BUILD_REGISTRY:+${BUILD_REGISTRY}/}pmacct-build-image AS build-stage



RUN apt-get update && apt-get install -y \
    curl \
    rustup \
    clang

WORKDIR /tmp/pmacct/src/external_libs/libcdada/

RUN autoreconf -fi && ./configure && make install && make clean

RUN ldconfig

RUN rustup toolchain install nightly

RUN rustup default nightly

RUN cargo install --git https://github.com/network-analytics/cargo-c cargo-c

WORKDIR /usr/pmacct-gauze
COPY . .

RUN cargo clean

RUN PMACCT_INCLUDE_DIR="/tmp" cargo cinstall -vv --package pmacct-gauze-lib
RUN ldconfig

WORKDIR /usr/pmacct-gauze/poc_gauze_lib

RUN autoreconf -fi

RUN ./configure 

RUN PMACCT_INCLUDE_DIR="/tmp/pmacct/src" make


CMD ["/bin/bash"]

# COPY --from=0 /tmp/pmacct-gauze/poc_gauze_lib/src/.libs/libparse.so /