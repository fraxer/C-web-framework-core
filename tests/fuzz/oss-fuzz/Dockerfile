# Builder image for OSS-Fuzz / ClusterFuzzLite.
#
# Only the -dev packages the framework links against, minus the HTTP/3 side:
# INCLUDE_HTTP3 wants OpenSSL 3.5 and this base has an older one, which is why
# build.sh turns it off.
FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        ninja-build \
        zip \
        libpcre2-dev \
        zlib1g-dev \
        libssl-dev \
        libxml2-dev \
        libidn2-dev \
        libunistring-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/fraxer/C-web-framework-core.git cwfr
WORKDIR cwfr
COPY build.sh $SRC/
