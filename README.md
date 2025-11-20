# media-server

Scripts and configuration for running a self-hosted media stack with Plex, Radarr, Sonarr, and Transmission via Docker Compose.

## Prerequisites
- Linux/macOS host with Docker Engine and the Docker Compose plugin (or `docker-compose`)
- Open ports 32400 (Plex), 7878 (Radarr), 8989 (Sonarr), 9091 (Transmission web/RPC), and 51413 TCP/UDP (Transmission peers) on your LAN or allow them via UFW
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
   Use subcommand names directly (e.g. `rollback` without a leading dash). The script also accepts `-rollback`/`--rollback` for convenience.
4. Access the services:
   - Plex: `http://<host>:32400/web` (host networking, so no explicit port mapping)
   - Radarr: `http://<host>:7878`
   - Sonarr: `http://<host>:8989`
   - Transmission: `http://<host>:9091`

Persistent data lives under the paths defined in `.env` (defaults to `media-data/` next to the repo). Back up those directories to preserve your configuration and libraries.

## Transmission integration
- Transmission shares the same `/downloads` volume as Radarr and Sonarr, so completed downloads are instantly visible to the indexers.
- Set `TRANSMISSION_RPC_USERNAME` / `TRANSMISSION_RPC_PASSWORD` (optional but recommended) and use the service name `transmission` with port `${TRANSMISSION_RPC_PORT}` when configuring the Download Client inside Radarr/Sonarr.
- The Web UI and RPC share the same TCP port, so exposing `${TRANSMISSION_WEB_PORT}` once makes both interfaces reachable.
- The deploy script pre-creates `watch` and `incomplete` folders under `MEDIA_DOWNLOADS_DIR` so Transmission's watch directory and incomplete folder work out of the box.

## Firewall automation
- Define `MEDIA_LOCAL_NETWORK_CIDR` (for example `192.168.1.0/24`) in `.env`. The deploy script enables UFW (if needed) and allows Plex, Radarr, Sonarr, and Transmission ports from that CIDR automatically.
- Optional `MEDIA_EXTRA_TCP_PORTS` lets you open additional TCP ports (comma-separated) for the same CIDR.
- Rollback removes every firewall rule the deploy step created, restoring the host to its previous state.
