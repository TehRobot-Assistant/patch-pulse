# PatchPulse — release notes + CVE context for Docker container updates.
#
# Shape matches tehrobot/docker-manager: simple, runs as root inside the
# container, single /config data volume. No multi-user namespace dance.
# Security comes from compose-level constraints (read_only, cap_drop,
# no-new-privileges) + the fact that the Docker socket is the most
# sensitive thing we touch and that's already governed by the user's
# compose choices.

# --- build stage -----------------------------------------------------------
FROM golang:1.26-bookworm AS build

ARG VERSION=dev
ARG COMMIT=none
ARG BUILDTIME=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILDTIME}" \
    -o /out/patchpulse \
    ./cmd/patchpulse

# --- grype install stage ---------------------------------------------------
FROM debian:bookworm-slim AS grype-install

ARG GRYPE_VERSION=0.86.1

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
      -o /tmp/grype.tgz \
    && tar -xzf /tmp/grype.tgz -C /tmp \
    && install -m 0755 /tmp/grype /usr/local/bin/grype \
    && rm -rf /tmp/grype /tmp/grype.tgz

# --- runtime stage ---------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/TehRobot-Assistant/patch-pulse"
LABEL org.opencontainers.image.description="Release notes + CVE context for your Docker container updates"
LABEL org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      apprise \
      wget \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /config

COPY --from=build /out/patchpulse /usr/local/bin/patchpulse
COPY --from=grype-install /usr/local/bin/grype /usr/local/bin/grype

WORKDIR /config

EXPOSE 8921

# Intentionally NO `ENV CONFIG_PATH` / `ENV PORT` here. The Go binary
# defaults to /config and 8921 if those env vars are unset; declaring
# them would cause Unraid to surface them as container variables that
# duplicate the path + port mapping in the UI (user sees the same
# setting twice and can accidentally desync them).
#
# Grype's vulnerability DB cache IS worth pinning via env — it's an
# internal Grype setting, not a redundant Docker mapping.
ENV GRYPE_DB_CACHE_DIR=/config/grype-db

VOLUME ["/config"]

# Container healthcheck calls our own /health endpoint. Always reachable
# (no auth required) so this works even before first-run setup.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8921/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/patchpulse"]
