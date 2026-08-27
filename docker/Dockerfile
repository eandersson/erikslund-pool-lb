# GCC 16.2 development, test, and static-analysis toolchain.
FROM gcc:16.2.0-trixie@sha256:b69972d6afe6d5f6c7f91ae30027caf8a50549ee25b63031071383d00941bf2f

ARG GLAZE_TAG=v8.2.0
ARG MIMALLOC_TAG=v3.5.0
ARG ERIKSLUND_HTTP_EMBEDDED_TAG=0.1.2
ARG CA_CERTIFICATES_VERSION=20250419
ARG CLANG_TIDY_VERSION=1:19.0-63
ARG CMAKE_VERSION=3.31.6-2
ARG CPPCHECK_VERSION=2.17.1-2
ARG DOCTEST_VERSION=2.4.11-1
ARG GIT_VERSION=1:2.47.3-0+deb13u1
ARG LIBSSL_DEV_VERSION=3.5.6-1~deb13u2
ARG MAKE_VERSION=4.4.1-2
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates="${CA_CERTIFICATES_VERSION}" clang-tidy="${CLANG_TIDY_VERSION}" \
        cmake="${CMAKE_VERSION}" cppcheck="${CPPCHECK_VERSION}" \
        doctest-dev="${DOCTEST_VERSION}" git="${GIT_VERSION}" \
        libssl-dev="${LIBSSL_DEV_VERSION}" make="${MAKE_VERSION}" \
    && rm -rf /var/lib/apt/lists/*
RUN git init /tmp/glaze \
    && git -C /tmp/glaze remote add origin https://github.com/stephenberry/glaze.git \
    && git -C /tmp/glaze fetch --depth 1 origin "refs/tags/${GLAZE_TAG}" \
    && git -C /tmp/glaze checkout --detach FETCH_HEAD \
    && cp -r /tmp/glaze/include/glaze /usr/local/include/glaze \
    && rm -rf /tmp/glaze
RUN git init /tmp/mimalloc \
    && git -C /tmp/mimalloc remote add origin https://github.com/microsoft/mimalloc.git \
    && git -C /tmp/mimalloc fetch --depth 1 origin "refs/tags/${MIMALLOC_TAG}" \
    && git -C /tmp/mimalloc checkout --detach FETCH_HEAD \
    && cmake -S /tmp/mimalloc -B /tmp/mimalloc/build -DCMAKE_BUILD_TYPE=Release \
        -DMI_INSTALL_TOPLEVEL=ON -DMI_BUILD_TESTS=OFF \
    && cmake --build /tmp/mimalloc/build -j"$(nproc)" \
    && cmake --install /tmp/mimalloc/build \
    && rm -rf /tmp/mimalloc \
    && ldconfig
RUN git init /tmp/erikslund-http-embedded \
    && git -C /tmp/erikslund-http-embedded remote add origin \
        https://github.com/eandersson/erikslund-http-embedded.git \
    && git -C /tmp/erikslund-http-embedded fetch --depth 1 origin \
        "refs/tags/${ERIKSLUND_HTTP_EMBEDDED_TAG}" \
    && git -C /tmp/erikslund-http-embedded checkout --detach FETCH_HEAD \
    && cmake -S /tmp/erikslund-http-embedded -B /tmp/erikslund-http-embedded/build \
        -DCMAKE_BUILD_TYPE=Release -DNATIVE_ARCH=OFF \
        -DERIKSLUND_HTTP_BUILD_TESTS=OFF -DERIKSLUND_HTTP_BUILD_EXAMPLES=OFF \
        -DERIKSLUND_HTTP_BUILD_TOOLS=OFF -DERIKSLUND_HTTP_BUILD_BENCH=OFF \
        -DERIKSLUND_HTTP_TLS=OFF -DERIKSLUND_HTTP_ZLIB=OFF \
        -DERIKSLUND_HTTP_CONTRACTS=OFF -DERIKSLUND_HTTP_REFLECTION=OFF \
        -DERIKSLUND_HTTP_STACKTRACE=OFF \
    && cmake --build /tmp/erikslund-http-embedded/build -j"$(nproc)" \
    && cmake --install /tmp/erikslund-http-embedded/build \
    && rm -rf /tmp/erikslund-http-embedded

COPY docker/clang-tidy.sh /usr/local/bin/clang-tidy.sh
COPY docker/cppcheck.sh /usr/local/bin/cppcheck.sh
RUN chmod +x /usr/local/bin/clang-tidy.sh /usr/local/bin/cppcheck.sh

WORKDIR /build
