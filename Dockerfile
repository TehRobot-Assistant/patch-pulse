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
# buildx sets TARGETARCH automatically — pick the right binary per platform
# so the arm64 manifest isn't just an amd64 grype masquerading as arm.
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN GRYPE_ARCH="${TARGETARCH:-amd64}" \
    && curl -sSfL \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${GRYPE_ARCH}.tar.gz" \
      -o /tmp/grype.tgz \
    && tar -xzf /tmp/grype.tgz -C /tmp \
    && install -m 0755 /tmp/grype /usr/local/bin/grype \
    && rm -rf /tmp/grype /tmp/grype.tgz

# --- docker CLI + compose plugin stage ------------------------------------
# Install the Docker CLI + compose v2 plugin as standalone binaries so the
# runtime image doesn't pull in containerd, runc, iptables, and ~250 MB of
# other dependencies from the `docker.io` Debian package — we only need the
# client to talk to the host's daemon via the mounted socket.
FROM debian:bookworm-slim AS docker-install

ARG DOCKER_VERSION=27.3.1
ARG COMPOSE_VERSION=2.29.7
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && case "${TARGETARCH:-amd64}" in \
        amd64) DOCKER_ARCH=x86_64;  COMPOSE_ARCH=x86_64  ;; \
        arm64) DOCKER_ARCH=aarch64; COMPOSE_ARCH=aarch64 ;; \
        *)     DOCKER_ARCH=x86_64;  COMPOSE_ARCH=x86_64  ;; \
       esac \
    # Docker CLI (just the client — no daemon).
    && curl -sSfL \
        "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-${DOCKER_VERSION}.tgz" \
        -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /tmp \
    && install -m 0755 /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker /tmp/docker.tgz \
    # Compose v2 plugin.
    && mkdir -p /usr/libexec/docker/cli-plugins \
    && curl -sSfL \
        "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${COMPOSE_ARCH}" \
        -o /usr/libexec/docker/cli-plugins/docker-compose \
    && chmod 0755 /usr/libexec/docker/cli-plugins/docker-compose

# --- runtime stage ---------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/TehRobot-Assistant/patch-pulse"
LABEL org.opencontainers.image.description="Release notes + CVE context for your Docker container updates"
LABEL org.opencontainers.image.licenses="MIT"

# Unraid UI hints — these make the WebUI link work on the Docker tab even
# when a user added the image via "Add Container" (no CA template). The
# [IP]/[PORT:8921] tokens are expanded by Unraid at render time.
LABEL net.unraid.docker.webui="http://[IP]:[PORT:8921]"
LABEL net.unraid.docker.icon="https://raw.githubusercontent.com/TehRobot-Assistant/patch-pulse/main/icon.png"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      apprise \
      wget \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /config

# The `docker` and `docker compose` CLIs are copied in from the
# docker-install stage as standalone static binaries (saves ~250 MB over
# the Debian docker.io package + its transitive deps). They only talk to
# the host daemon via the mounted socket — no dockerd inside this image.

COPY --from=build /out/patchpulse /usr/local/bin/patchpulse
COPY --from=grype-install /usr/local/bin/grype /usr/local/bin/grype
COPY --from=docker-install /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-install /usr/libexec/docker/cli-plugins/docker-compose /usr/libexec/docker/cli-plugins/docker-compose

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
