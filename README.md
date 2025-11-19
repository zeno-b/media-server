# media-server

Scripts and configuration for running a self-hosted media stack with Plex, Radarr, and Sonarr via Docker Compose.

## Prerequisites
- Linux/macOS host with Docker Engine and the Docker Compose plugin (or `docker-compose`)
- Open ports 32400 (Plex), 7878 (Radarr), 8989 (Sonarr) on your LAN
- Plex account (optional but required to claim the server)

## Quick start
1. Copy the sample environment file and edit it:
   ```bash
   cp .env.example .env
   ```
   Update `TZ`, `PUID`, `PGID`, storage paths, and optionally `PLEX_CLAIM`/`PLEX_ADVERTISE_IP`.
2. Deploy (or manage) the stack:
   ```bash
   ./deploy_media_stack.sh          # default: docker compose up -d
   ./deploy_media_stack.sh down     # stop and remove containers
   ./deploy_media_stack.sh pull     # update images
   ```
   The script ensures all bind-mounted directories exist before running Docker Compose.
3. Access the services:
   - Plex: `http://<host>:32400/web` (host networking, so no explicit port mapping)
   - Radarr: `http://<host>:7878`
   - Sonarr: `http://<host>:8989`

Persistent data lives under the paths defined in `.env` (defaults to `media-data/` next to the repo). Back up those directories to preserve your configuration and libraries. Remove the stack any time with `./deploy_media_stack.sh down`.
