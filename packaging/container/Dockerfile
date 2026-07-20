# syntax=docker/dockerfile:1

ARG DOTNET_RUNTIME_IMAGE=mcr.microsoft.com/dotnet/runtime-deps@sha256:894098eafc82e5fa02ba9f2b71d426dc78252876b9e914caae77ed95cfce185a

FROM ${DOTNET_RUNTIME_IMAGE}
ARG VERSION

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
COPY picket /usr/local/bin/picket
COPY picket-tui /usr/local/bin/picket-tui
COPY libzstd.so /usr/local/bin/libzstd.so
COPY LICENSE /licenses/Picket/LICENSE
COPY THIRD-PARTY-NOTICES.txt /licenses/Picket/THIRD-PARTY-NOTICES.txt

USER $APP_UID
ENTRYPOINT ["/usr/local/bin/picket"]
CMD ["--help"]
