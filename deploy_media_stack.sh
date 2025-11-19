#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${SCRIPT_DIR}/docker-compose.yml}"
DEFAULT_ENV_FILE="${SCRIPT_DIR}/.env"
ENV_FILE="${MEDIA_STACK_ENV:-$DEFAULT_ENV_FILE}"

log() {
  printf '[media-stack] %s\n' "$*"
}

fail() {
  printf '[media-stack][error] %s\n' "$*" >&2
  exit 1
}

ensure_command() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail "'$name' is required but not installed."
}

resolve_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$SCRIPT_DIR" "$path"
  fi
}

ensure_dir() {
  local raw_path="$1"
  local resolved
  resolved="$(resolve_path "$raw_path")"
  mkdir -p "$resolved"
  log "Ensured directory: $resolved"
}

[[ -f "$COMPOSE_FILE" ]] || fail "Missing docker-compose file at $COMPOSE_FILE"
[[ -f "$ENV_FILE" ]] || fail "Missing env file at $ENV_FILE. Copy .env.example to .env and customize it."

ensure_command docker

if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
else
  fail "Neither 'docker compose' nor 'docker-compose' is available."
fi

log "Loading configuration from $ENV_FILE"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

[[ -n "${MEDIA_CONFIG_DIR:-}" ]] || fail "MEDIA_CONFIG_DIR is not set in $ENV_FILE"
[[ -n "${MEDIA_MEDIA_DIR:-}" ]] || fail "MEDIA_MEDIA_DIR is not set in $ENV_FILE"
[[ -n "${MEDIA_DOWNLOADS_DIR:-}" ]] || fail "MEDIA_DOWNLOADS_DIR is not set in $ENV_FILE"

ensure_dir "$MEDIA_CONFIG_DIR/plex"
ensure_dir "$MEDIA_CONFIG_DIR/radarr"
ensure_dir "$MEDIA_CONFIG_DIR/sonarr"
ensure_dir "$MEDIA_MEDIA_DIR/movies"
ensure_dir "$MEDIA_MEDIA_DIR/tv"
ensure_dir "$MEDIA_DOWNLOADS_DIR"

ACTION=("$@")
if [[ ${#ACTION[@]} -eq 0 ]]; then
  ACTION=(up -d)
fi

log "Running: ${COMPOSE_CMD[*]} --env-file $ENV_FILE -f $COMPOSE_FILE ${ACTION[*]}"
"${COMPOSE_CMD[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "${ACTION[@]}"
