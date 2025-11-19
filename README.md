# media-server

Scripts and configuration for running a self-hosted media stack with Plex, Radarr, and Sonarr via Docker Compose.

## Prerequisites
- Linux/macOS host with Docker Engine and the Docker Compose plugin (or `docker-compose`)
- Open ports 32400 (Plex), 7878 (Radarr), 8989 (Sonarr) on your LAN
- Plex account (optional but required to claim the server)

## Quick start
1. Configure environment variables  
   - On first run the deploy script will automatically copy `.env.example` to `.env` if it does not exist.  
   - Update `TZ`, `PUID`, `PGID`, storage paths, and optionally `PLEX_CLAIM`/`PLEX_ADVERTISE_IP` to match your host.
2. Deploy or manage the stack:
   ```bash
   ./deploy_media_stack.sh             # default "deploy" (docker compose up -d)
   ./deploy_media_stack.sh deploy --build   # pass extra flags to `docker compose up`
   ./deploy_media_stack.sh pull        # forward arbitrary commands to docker compose
   ```
   The script verifies Docker/Docker Compose availability, loads the `.env`, and creates all required directories before running Compose.
3. Roll back everything (containers, images, volumes, configs, downloads, and library folders created by the stack):
   ```bash
   ./deploy_media_stack.sh rollback
   ```
   **Warning:** rollback deletes `MEDIA_CONFIG_DIR`, `MEDIA_DOWNLOADS_DIR`, and the `movies`/`tv` subfolders under `MEDIA_MEDIA_DIR`.
4. Access the services:
   - Plex: `http://<host>:32400/web` (host networking, so no explicit port mapping)
   - Radarr: `http://<host>:7878`
   - Sonarr: `http://<host>:8989`

Persistent data lives under the paths defined in `.env` (defaults to `media-data/` next to the repo). Back up those directories to preserve your configuration and libraries.
