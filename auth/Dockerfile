FROM ghcr.io/ziglang/zig:0.14.0 AS build
WORKDIR /app
COPY build.zig build.zig.zon src/ src/
RUN zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSafe

FROM public.ecr.aws/awsguru/aws-lambda-web-adapter:0.8.4-arm64 AS adapter

FROM public.ecr.aws/lambda/provided:al2023-arm64
COPY --from=adapter /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=build /app/zig-out/bin/ape-auth /usr/local/bin/ape-auth
ENV READINESS_CHECK_PATH=/health
CMD ["/usr/local/bin/ape-auth"]
