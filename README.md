# PatchPulse

Release notes + CVE context for your Docker container updates. Install and run — no config files, no CLI dance.

> **Pre-release beta.** Report issues via the [issue tracker](https://github.com/TehRobot-Assistant/patch-pulse/issues).

## What it does

- Reads your Docker socket to list every running container
- Polls Docker Hub / GHCR / Quay for new image versions (default every 6 hours)
- Fetches the **release notes** when a new version appears (GitHub Releases API → `CHANGELOG.md` → commit log)
- Scans your currently-running image for **unfixed CVEs** via bundled Grype
- Shows it all in a web UI — one row per container
- Optional: **Update now** button that runs `docker compose pull && up -d` against the stack's compose file, gated by a service-name confirmation

Diun tells you a new version exists. What's Up Docker adds scheduling. Neither shows you the changelog or flags CVEs in the version you're running. PatchPulse does.

## Quick start

```yaml
services:
  patchpulse:
    image: tehrobot/patch-pulse:latest
    container_name: patchpulse
    ports:
      - "8921:8921"
    volumes:
      - ./config:/config
      - /var/run/docker.sock:/var/run/docker.sock:ro
    restart: unless-stopped
```

```bash
docker compose up -d
```

Open **http://\<host\>:8921** → create admin via the first-run wizard → done.

## Unraid

Install via Unraid's **Docker Compose Manager** plugin, pointing at this repo's `docker-compose.yml` (or paste it into a new stack). Appdata mount convention is `/mnt/user/appdata/patchpulse → /config`.

## Documentation

- [DOCKERHUB.md](DOCKERHUB.md) — full reference, settings, env vars, Docker Hub tag list
- [test/smoke.sh](test/smoke.sh) — end-to-end test of the built image

## Development

```bash
# Run the full end-to-end smoke test against a locally-built image
./test/smoke.sh

# Build the binary locally (no Docker)
go build -o ./out/patchpulse ./cmd/patchpulse
```

### CI / release flow

- Push to `main` → GitHub Actions builds and publishes `tehrobot/patch-pulse:latest` + `ghcr.io/tehrobot-assistant/patch-pulse:latest`
- Push a git tag `v0.2.0` → publishes `:0.2.0` + `:0.2` + `:latest`

## Licence

MIT. Part of TR Studios.
