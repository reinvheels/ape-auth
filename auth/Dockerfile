FROM debian:bookworm-slim AS build
ARG ZIG_URL=https://ziglang.org/builds/zig-aarch64-linux-0.16.0-dev.2682+02142a54d.tar.xz
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates xz-utils curl \
    && mkdir -p /opt/zig \
    && curl -fSL "${ZIG_URL}" | tar -xJ --strip-components=1 -C /opt/zig \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/zig:${PATH}"
WORKDIR /app
COPY build.zig build.zig.zon ./
COPY src/ src/
RUN zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSafe

FROM alpine:3 AS runtime
RUN mkdir -p /opt/extensions /tmp
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:1.0.0-rc1 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=build /app/zig-out/bin/ape-auth /var/runtime/bootstrap
ENV AWS_LWA_READINESS_CHECK_PATH=/health
ENTRYPOINT ["/var/runtime/bootstrap"]
