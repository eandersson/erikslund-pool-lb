# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM gcc:16.2.0-trixie@sha256:b69972d6afe6d5f6c7f91ae30027caf8a50549ee25b63031071383d00941bf2f AS builder

ARG GLAZE_COMMIT=be4481f4b106fc82f0b7bc85f6a92202f8c0dd59
ARG MIMALLOC_COMMIT=acf2fdd329f9dc2a7ffe3f12a133fe7175e39378
ARG ERIKSLUND_HTTP_EMBEDDED_COMMIT=b6b27c2f26b69fe12e38a2d594ade096dddcc1ef
ARG CA_CERTIFICATES_VERSION=20250419
ARG CMAKE_VERSION=3.31.6-2
ARG GIT_VERSION=1:2.47.3-0+deb13u1
ARG LIBSSL_DEV_VERSION=3.5.6-1~deb13u2
ARG MAKE_VERSION=4.4.1-2
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates="${CA_CERTIFICATES_VERSION}" cmake="${CMAKE_VERSION}" \
        git="${GIT_VERSION}" libssl-dev="${LIBSSL_DEV_VERSION}" make="${MAKE_VERSION}" \
    && rm -rf /var/lib/apt/lists/*
RUN git init /tmp/glaze \
    && git -C /tmp/glaze remote add origin https://github.com/stephenberry/glaze.git \
    && git -C /tmp/glaze fetch --depth 1 origin "${GLAZE_COMMIT}" \
    && git -C /tmp/glaze checkout --detach FETCH_HEAD \
    && cp -r /tmp/glaze/include/glaze /usr/local/include/glaze \
    && rm -rf /tmp/glaze
RUN git init /tmp/mimalloc \
    && git -C /tmp/mimalloc remote add origin https://github.com/microsoft/mimalloc.git \
    && git -C /tmp/mimalloc fetch --depth 1 origin "${MIMALLOC_COMMIT}" \
    && git -C /tmp/mimalloc checkout --detach FETCH_HEAD \
    && cmake -S /tmp/mimalloc -B /tmp/mimalloc/build -DCMAKE_BUILD_TYPE=Release \
        -DMI_INSTALL_TOPLEVEL=ON -DMI_BUILD_TESTS=OFF \
    && cmake --build /tmp/mimalloc/build -j"$(nproc)" \
    && cmake --install /tmp/mimalloc/build \
    && rm -rf /tmp/mimalloc
RUN git init /tmp/erikslund-http-embedded \
    && git -C /tmp/erikslund-http-embedded remote add origin \
        https://github.com/eandersson/erikslund-http-embedded.git \
    && git -C /tmp/erikslund-http-embedded fetch --depth 1 origin \
        "${ERIKSLUND_HTTP_EMBEDDED_COMMIT}" \
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

WORKDIR /src
COPY CMakeLists.txt ./
COPY src/ src/
RUN cmake -S . -B /build -DCMAKE_BUILD_TYPE=Release -DNATIVE_ARCH=OFF -DBUILD_TESTING=OFF \
    && cmake --build /build --target erikslund-pool-lb -j"$(nproc)" \
    && ldconfig \
    && mkdir -p /runtime-libs \
    && ldd /build/erikslund-pool-lb \
       | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' \
       | sort -u \
       | xargs -r -I '{}' cp -L '{}' /runtime-libs/

FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258 AS runtime

RUN groupadd --gid 1000 pool-lb \
    && useradd --uid 1000 --gid pool-lb --no-create-home --shell /usr/sbin/nologin pool-lb
COPY --from=builder /runtime-libs/ /usr/local/lib/pool-lb/
COPY --from=builder /build/erikslund-pool-lb /usr/local/bin/erikslund-pool-lb
COPY conf/pool-lb.example.yml /etc/erikslund-pool-lb/pool-lb.example.yml
ENV LD_LIBRARY_PATH=/usr/local/lib/pool-lb

USER pool-lb
EXPOSE 3333 3334 7778
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
    CMD ["erikslund-pool-lb", "--health-check", "127.0.0.1:7778"]
ENTRYPOINT ["erikslund-pool-lb"]
CMD ["--config", "/etc/erikslund-pool-lb/pool-lb.yml"]
