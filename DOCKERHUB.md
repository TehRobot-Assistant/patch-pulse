# PatchPulse

**Release notes + CVE context for your Docker container updates.** Install and run — no config files, no CLI dance.

⚠️ **Pre-release beta.** Report issues: [GitHub](https://github.com/TehRobot-Assistant/patch-pulse/issues).

## What it does

- Reads your Docker socket to list every running container
- Polls Docker Hub / GHCR / Quay for new image versions (default every 6 hours)
- Fetches the **release notes** when a new version appears (GitHub Releases API → CHANGELOG.md → commit log)
- Scans your currently-running image for **unfixed CVEs** via bundled Grype
- Shows it all in a web UI — one row per container
- Optional: **Update now** button that runs `docker compose pull && up -d` against the stack's compose file, gated by a service-name confirmation

Diun tells you a new version exists. What's Up Docker adds scheduling. Neither shows you the changelog or flags the CVEs in the version you're running. PatchPulse does.

## Quick start — zero config

```yaml
services:
  patchpulse:
    image: tehrobot/patchpulse:latest
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

Open **http://\<host\>:8921** → create admin via the first-run wizard → done. No YAML file to edit, no CLI commands, no restart.

## Unraid setup

Template appdata path is **`/mnt/user/appdata/patchpulse`** → mapped to **`/config`** in the container. Matches the standard Unraid convention (same shape as Sonarr, Radarr, Jellyfin). Everything — SQLite DB, Grype vulnerability cache, all settings — lives under that one path.

## Environment variables

All optional. Everything can also be set via the Settings page in the web UI.

| Var | Default | Purpose |
|---|---|---|
| `PORT` | `8921` | HTTP listen port |
| `CONFIG_PATH` | `/config` | Data directory (SQLite + Grype DB cache) |
| `ADMIN_USERNAME` | `admin` | Seed admin username on first start |
| `ADMIN_PASSWORD` | _(unset)_ | Seed admin password. If unset, first-visit web wizard collects it. |
| `DOCKER_HOST` | `/var/run/docker.sock` | Path to Docker socket (rarely needs changing) |

## The Update now button

Off by default. When enabled (Settings page):

- Only works for containers started via Docker Compose (has `com.docker.compose.project` label)
- Requires the stack's compose file to be mounted into the PatchPulse container so it can `cd` there
- Requires a read-write Docker socket (remove the `:ro` from the compose mount)
- Requires you to re-type the service name as a confirmation token

Containers started with `docker run` or via Portainer show the changelog + CVE info but no button — managed externally.

## GitHub PAT (recommended)

Anonymous GitHub API: 60 req/hour. A read-only `public_repo` PAT: 5000 req/hour. Paste it into Settings if you monitor 20+ containers.

## What's in the image

- Go binary, statically linked, no CGO
- Debian Bookworm base
- Bundled: **Grype** (CVE scanner) + **Apprise** (notification fan-out to 110+ services)
- Runs as root inside the container — intentional for simple bind-mount compatibility. Security at the compose level (read-only Docker socket, cap_drop ALL, read-only rootfs if you want).

## Tags

| Tag | Use |
|---|---|
| `latest` | Current stable / beta release |
| `beta` | Rolling pre-release |
| `0.1.0-beta` | Pinned version |

## Links

- [GitHub](https://github.com/TehRobot-Assistant/patch-pulse)
- [Issues](https://github.com/TehRobot-Assistant/patch-pulse/issues)

MIT licence. Part of [TR Studios](https://tehrobot-servers.com) — pairs with [RestoreRunner](https://hub.docker.com/r/tehrobot/restorerunner) (backup restore rehearsal).
