# syntax=docker/dockerfile:1

ARG DOTNET_SDK_IMAGE=mcr.microsoft.com/dotnet/sdk@sha256:ed034a8bf0b24ded0cbbac07e17825d8e9ebfe21e308191d0f7421eaf5ad4664
ARG DOTNET_RUNTIME_IMAGE=mcr.microsoft.com/dotnet/runtime-deps@sha256:894098eafc82e5fa02ba9f2b71d426dc78252876b9e914caae77ed95cfce185a

FROM ${DOTNET_SDK_IMAGE} AS build
ARG TARGETARCH
ARG RID
ARG VERSION=0.1.0

WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN dotnet restore Picket.slnx --locked-mode
RUN if [ -z "$RID" ]; then \
        case "$TARGETARCH" in \
            amd64) export RID=linux-x64 ;; \
            arm64) export RID=linux-arm64 ;; \
            *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
        esac; \
    fi \
    && dotnet publish src/Picket.Cli/Picket.Cli.csproj --configuration Release -p:PublishProfile=release-speed -p:Version="$VERSION" -p:PackageVersion="$VERSION" -r "$RID" --no-restore -o /out \
    && dotnet publish src/Picket.Tui.Cli/Picket.Tui.Cli.csproj --configuration Release -p:PublishProfile=release-speed -p:Version="$VERSION" -p:PackageVersion="$VERSION" -r "$RID" --no-restore -o /out

FROM ${DOTNET_RUNTIME_IMAGE} AS runtime
ARG VERSION=0.1.0

LABEL org.opencontainers.image.title="Picket"
LABEL org.opencontainers.image.description="Gitleaks-compatible Native AOT secrets scanner for .NET."
LABEL org.opencontainers.image.source="https://github.com/willibrandon/picket"
LABEL org.opencontainers.image.licenses="MIT AND BSD-3-Clause"
LABEL org.opencontainers.image.version="$VERSION"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && git config --system --add safe.directory /work \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY --from=build /out/picket /usr/local/bin/picket
COPY --from=build /out/picket-tui /usr/local/bin/picket-tui
COPY --from=build /out/libzstd.so /usr/local/bin/libzstd.so
COPY --from=build /src/LICENSE /licenses/Picket/LICENSE
COPY --from=build /src/THIRD-PARTY-NOTICES.txt /licenses/Picket/THIRD-PARTY-NOTICES.txt

USER $APP_UID
ENTRYPOINT ["/usr/local/bin/picket"]
CMD ["--help"]
