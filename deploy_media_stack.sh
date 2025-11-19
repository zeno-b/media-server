#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
  printf '[media-stack] %s\n' "$*"
}

fail() {
  printf '[media-stack][error] %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: deploy_media_stack.sh [command]

Commands
  deploy            Ensure prerequisites, create needed directories, and run `docker compose up -d`.
                    This is the default command when none is provided.
  rollback          Stop the stack, remove containers, images, volumes, and delete all created data directories.
  help              Show this help text.
  <compose args...> Any other command is forwarded directly to docker compose (env + compose file are injected).

Environment
  MEDIA_STACK_ENV   Path to the .env file to use (defaults to .env next to this script).
  COMPOSE_FILE      Override the docker-compose file (defaults to docker-compose.yml next to this script).
EOF
}

ensure_command() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail "'$name' is required but not installed."
}

resolve_path() {
  local path="$1"
  if [[ -z "$path" ]]; then
    fail "resolve_path received an empty value"
  fi
  if [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$SCRIPT_DIR" "$path"
  fi
}

DEFAULT_COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
COMPOSE_FILE_INPUT="${COMPOSE_FILE:-$DEFAULT_COMPOSE_FILE}"
DEFAULT_ENV_FILE="${SCRIPT_DIR}/.env"
ENV_FILE_INPUT="${MEDIA_STACK_ENV:-$DEFAULT_ENV_FILE}"
ENV_TEMPLATE_FILE_INPUT="${SCRIPT_DIR}/.env.example"

COMPOSE_FILE="$(resolve_path "$COMPOSE_FILE_INPUT")"
ENV_FILE="$(resolve_path "$ENV_FILE_INPUT")"
ENV_TEMPLATE_FILE="$(resolve_path "$ENV_TEMPLATE_FILE_INPUT")"

ensure_dir() {
  local raw_path="$1"
  [[ -n "$raw_path" ]] || fail "Directory path is required"
  local resolved
  resolved="$(resolve_path "$raw_path")"
  mkdir -p "$resolved"
  log "Ensured directory: $resolved"
}

remove_dir() {
  local raw_path="$1"
  [[ -n "$raw_path" ]] || return 0
  local resolved
  resolved="$(resolve_path "$raw_path")"
  if [[ "$resolved" == "/" ]]; then
    fail "Refusing to remove root directory"
  fi
  if [[ -e "$resolved" ]]; then
    rm -rf "$resolved"
    log "Removed: $resolved"
  else
    log "Already removed: $resolved"
  fi
}

ensure_env_file() {
  local allow_bootstrap="${1:-false}"
  if [[ -f "$ENV_FILE" ]]; then
    return 0
  fi

  if [[ "$allow_bootstrap" == "true" ]]; then
    if [[ -f "$ENV_TEMPLATE_FILE" ]]; then
      cp "$ENV_TEMPLATE_FILE" "$ENV_FILE"
      log "Created $ENV_FILE from template $ENV_TEMPLATE_FILE. Review and update values as needed."
    else
      fail "Missing env file ($ENV_FILE) and template ($ENV_TEMPLATE_FILE)."
    fi
  else
    fail "Missing env file at $ENV_FILE. Set MEDIA_STACK_ENV or create it from $ENV_TEMPLATE_FILE."
  fi
}

load_env() {
  log "Loading configuration from $ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
}

ensure_required_env_vars() {
  local missing=()
  local required_vars=(PUID PGID TZ MEDIA_CONFIG_DIR MEDIA_MEDIA_DIR MEDIA_DOWNLOADS_DIR)
  for var in "${required_vars[@]}"; do
    if [[ -z "${!var:-}" ]]; then
      missing+=("$var")
    fi
  done

  if ((${#missing[@]} > 0)); then
    fail "Missing required variable(s) in $ENV_FILE: ${missing[*]}"
  fi
}

prepare_directories() {
  ensure_dir "$MEDIA_CONFIG_DIR/plex"
  ensure_dir "$MEDIA_CONFIG_DIR/radarr"
  ensure_dir "$MEDIA_CONFIG_DIR/sonarr"
  ensure_dir "$MEDIA_MEDIA_DIR/movies"
  ensure_dir "$MEDIA_MEDIA_DIR/tv"
  ensure_dir "$MEDIA_DOWNLOADS_DIR"
}

COMPOSE_CMD=()

determine_compose_cmd() {
  ensure_command docker

  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
  else
    fail "Neither 'docker compose' nor 'docker-compose' is available."
  fi
}

run_compose() {
  local args=("$@")
  log "Running: ${COMPOSE_CMD[*]} --env-file $ENV_FILE -f $COMPOSE_FILE ${args[*]}"
  "${COMPOSE_CMD[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "${args[@]}"
}

deploy_stack() {
  local extra_up_args=("$@")
  prepare_directories

  local up_args
  if ((${#extra_up_args[@]} > 0)); then
    up_args=("up" "${extra_up_args[@]}")
  else
    up_args=("up" "-d")
  fi

  run_compose "${up_args[@]}"
}

rollback_stack() {
  log "Stopping and removing containers, networks, images, and volumes..."
  run_compose down --volumes --remove-orphans --rmi all

  log "Removing persistent data directories..."
  remove_dir "$MEDIA_CONFIG_DIR"
  remove_dir "$MEDIA_DOWNLOADS_DIR"
  remove_dir "$MEDIA_MEDIA_DIR/movies"
  remove_dir "$MEDIA_MEDIA_DIR/tv"

  log "Rollback complete."
}

main() {
  [[ -f "$COMPOSE_FILE" ]] || fail "Missing docker-compose file at $COMPOSE_FILE"

  local action
  if (($# == 0)); then
    action="deploy"
  else
    action="$1"
    shift
  fi

  case "$action" in
    help|-h|--help)
      usage
      ;;
    deploy)
      ensure_env_file "true"
      load_env
      ensure_required_env_vars
      determine_compose_cmd
      deploy_stack "$@"
      ;;
    rollback)
      ensure_env_file "false"
      load_env
      ensure_required_env_vars
      determine_compose_cmd
      rollback_stack
      ;;
    *)
      ensure_env_file "true"
      load_env
      ensure_required_env_vars
      if [[ "$action" == "up" ]]; then
        prepare_directories
      fi
      determine_compose_cmd
      run_compose "$action" "$@"
      ;;
  esac
}

main "$@"
