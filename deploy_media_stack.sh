#!/usr/bin/env bash

# This directive enforces strict error handling, halting on undefined variables, command errors, or broken pipelines.
set -euo pipefail
# This directive standardizes word splitting to eliminate surprising whitespace behavior.
IFS=$'\n\t'
# This trap routes every unexpected error through the dedicated handler so failures always log contextual information.
trap 'handle_error $? $LINENO' ERR

# This variable stores the directory that contains this script so relative paths remain stable no matter where we run from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# This variable defines where docker-compose.yml is expected to live by default unless COMPOSE_FILE overrides it.
DEFAULT_COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
# This variable captures a user override for compose configuration, falling back to the default path when unset.
COMPOSE_FILE_INPUT="${COMPOSE_FILE:-$DEFAULT_COMPOSE_FILE}"
# This variable defines the default .env path so configuration lives alongside the script when not overridden.
DEFAULT_ENV_FILE="${SCRIPT_DIR}/.env"
# This variable captures a user-provided env file location while defaulting to the local .env file.
ENV_FILE_INPUT="${MEDIA_STACK_ENV:-$DEFAULT_ENV_FILE}"
# This variable points to the template env file so the script can bootstrap configuration automatically.
ENV_TEMPLATE_FILE_INPUT="${SCRIPT_DIR}/.env.example"
# This variable records the directory used to store deployment state artifacts (e.g., firewall rules) for safe rollback.
STATE_DIR="${SCRIPT_DIR}/.media_stack_state"
# This variable tracks the file that lists firewall rules added by the deploy workflow so rollback knows what to remove.
FIREWALL_STATE_FILE="${STATE_DIR}/firewall_rules"
# This variable defines how many attempts should be made when retrying transient operations (e.g., image pulls).
MAX_RETRIES=3
# This variable defines the base delay (in seconds) between retries to avoid hammering external services.
RETRY_DELAY_SECONDS=5
# This variable indicates which package manager should be used; currently only apt is supported.
PACKAGE_MANAGER=""
# This flag tracks whether the package index has already been refreshed to avoid redundant update calls.
PACKAGE_INDEX_REFRESHED=false
# This variable caches which privileged runner to use; it is empty when running as root and "sudo" otherwise.
SUDO_BIN=""
# This array captures the resolved docker compose command variant (plugin or legacy binary).
COMPOSE_CMD=()
# This array stores every TCP port that should be opened via the firewall for the stack.
FIREWALL_PORTS=()

# This function prints informational messages with a consistent prefix for easier log scanning.
log() {
  printf '[media-stack] %s\n' "$*"
}

# This function prints errors in a consistent format and then exits the script with a failure status.
fail() {
  printf '[media-stack][error] %s\n' "$*" >&2
  exit 1
}

# This function centralizes error trapping so we see line numbers and exit codes whenever something fails unexpectedly.
handle_error() {
  local exit_code="$1"
  local line="$2"
  fail "Command failed with exit code ${exit_code} at line ${line}."
}

# This function prints usage instructions so users understand every supported command and environment variable.
usage() {
  cat <<'EOF'
Usage: deploy_media_stack.sh [command]

Commands
  deploy            Install prerequisites, configure the firewall, pre-pull images, and run `docker compose up -d`.
                    This is the default action when no command is provided.
  rollback          Stop containers, remove images, volumes, firewall rules, and delete persistent data folders.
  help              Show this help text.
  <compose args...> Any other arguments are forwarded directly to docker compose after prerequisites are satisfied.

Environment
  MEDIA_STACK_ENV   Path to the .env file to use (defaults to .env next to this script).
  COMPOSE_FILE      Override the docker-compose file (defaults to docker-compose.yml next to this script).
  MEDIA_EXTRA_TCP_PORTS A comma-separated list of extra TCP ports to open in the firewall (optional).
EOF
}

# This function verifies that a required binary exists on the system before attempting to use it.
ensure_command() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail "'$name' is required but not installed."
}

# This function standardizes path resolution by converting relative inputs into absolute paths anchored at the script directory.
resolve_path() {
  local path="$1"
  if [[ -z "$path" ]]; then
    fail "resolve_path received an empty value."
  fi
  if [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$SCRIPT_DIR" "$path"
  fi
}

# This function determines which privilege elevation method should be used for system-level commands.
determine_privileged_runner() {
  if ((EUID == 0)); then
    SUDO_BIN=""
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    SUDO_BIN="sudo"
    return
  fi
  fail "This script requires root privileges. Please run as root or install sudo."
}

# This function executes a command with elevated privileges when needed while keeping the callsite simple.
run_privileged() {
  if [[ -n "$SUDO_BIN" ]]; then
    "$SUDO_BIN" "$@"
  else
    "$@"
  fi
}

# This function ensures the package manager is detected and supported before any installation attempts occur.
detect_package_manager() {
  if [[ -n "$PACKAGE_MANAGER" ]]; then
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    PACKAGE_MANAGER="apt"
    return
  fi
  fail "Unsupported package manager. Currently only apt-based systems are supported."
}

# This function refreshes the package index exactly once per run to minimize network calls.
refresh_package_index_once() {
  if [[ "$PACKAGE_MANAGER" != "apt" ]]; then
    fail "refresh_package_index_once currently supports only apt."
  fi
  if [[ "$PACKAGE_INDEX_REFRESHED" == "true" ]]; then
    return
  fi
  log "Refreshing package index..."
  run_privileged apt-get update >/dev/null
  PACKAGE_INDEX_REFRESHED=true
}

# This function checks whether the provided packages are installed and installs any missing entries.
install_packages_if_missing() {
  local packages=("$@")
  if [[ "${#packages[@]}" -eq 0 ]]; then
    return
  fi
  detect_package_manager
  case "$PACKAGE_MANAGER" in
    apt)
      local missing=()
      local pkg
      for pkg in "${packages[@]}"; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
      done
      if ((${#missing[@]} == 0)); then
        return
      fi
      refresh_package_index_once
      log "Installing missing packages: ${missing[*]}"
      run_privileged apt-get install -y "${missing[@]}" >/dev/null
      ;;
    *)
      fail "install_packages_if_missing is not implemented for package manager '$PACKAGE_MANAGER'."
      ;;
  esac
}

# This function installs every prerequisite required for the media stack, including Docker, docker compose, and ufw.
install_prerequisites() {
  local base_packages=(ca-certificates curl gnupg lsb-release ufw software-properties-common)
  install_packages_if_missing "${base_packages[@]}"
  local docker_packages=(docker.io docker-compose-plugin)
  install_packages_if_missing "${docker_packages[@]}"
  ensure_command docker
  ensure_command ufw
  ensure_docker_service_running
}

# This function ensures the Docker daemon is running and ready to accept API requests.
ensure_docker_service_running() {
  if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet docker; then
      log "Starting Docker service..."
      run_privileged systemctl enable --now docker >/dev/null
    fi
  fi
  if docker info >/dev/null 2>&1; then
    return
  fi
  if [[ -n "$SUDO_BIN" ]] && run_privileged docker info >/dev/null 2>&1; then
    return
  fi
  fail "Docker daemon is not reachable. Ensure your user belongs to the docker group or run this script with elevated privileges."
}

# This function ensures the deployment state directory exists so metadata can be recorded for rollback.
initialize_state_store() {
  mkdir -p "$STATE_DIR"
}

# This function records newly added firewall rules so the rollback flow can delete them later.
record_firewall_rule() {
  local rule="$1"
  initialize_state_store
  if [[ -f "$FIREWALL_STATE_FILE" ]] && grep -Fxq "$rule" "$FIREWALL_STATE_FILE"; then
    return
  fi
  printf '%s\n' "$rule" >>"$FIREWALL_STATE_FILE"
}

# This function removes the firewall state file after its contents have been processed.
clear_firewall_state() {
  if [[ -f "$FIREWALL_STATE_FILE" ]]; then
    rm -f "$FIREWALL_STATE_FILE"
  fi
}

# This function loads the stack's environment file so docker compose receives the correct variables.
load_env() {
  log "Loading configuration from $ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
}

# This function ensures the .env file exists, optionally seeding it from a template when allowed.
ensure_env_file() {
  local allow_bootstrap="${1:-false}"
  if [[ -f "$ENV_FILE" ]]; then
    return
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

# This function validates that every required environment variable has a value to prevent partial deployments.
ensure_required_env_vars() {
  local missing=()
  local required_vars=(PUID PGID TZ MEDIA_CONFIG_DIR MEDIA_MEDIA_DIR MEDIA_DOWNLOADS_DIR RADARR_PORT SONARR_PORT)
  local var
  for var in "${required_vars[@]}"; do
    if [[ -z "${!var:-}" ]]; then
      missing+=("$var")
    fi
  done
  if ((${#missing[@]} > 0)); then
    fail "Missing required variable(s) in $ENV_FILE: ${missing[*]}"
  fi
}

# This function ensures every directory needed by the containers exists with the right structure.
ensure_dir() {
  local raw_path="$1"
  if [[ -z "$raw_path" ]]; then
    fail "Directory path is required."
  fi
  local resolved
  resolved="$(resolve_path "$raw_path")"
  mkdir -p "$resolved"
  log "Ensured directory: $resolved"
}

# This function removes directories safely, guarding against accidental deletion of the filesystem root.
remove_dir() {
  local raw_path="$1"
  if [[ -z "$raw_path" ]]; then
    return 0
  fi
  local resolved
  resolved="$(resolve_path "$raw_path")"
  if [[ "$resolved" == "/" ]]; then
    fail "Refusing to remove root directory."
  fi
  if [[ -e "$resolved" ]]; then
    rm -rf "$resolved"
    log "Removed: $resolved"
  else
    log "Already removed: $resolved"
  fi
}

# This function prepares the filesystem tree expected by plex/radarr/sonarr prior to running docker compose.
prepare_directories() {
  ensure_dir "$MEDIA_CONFIG_DIR/plex"
  ensure_dir "$MEDIA_CONFIG_DIR/radarr"
  ensure_dir "$MEDIA_CONFIG_DIR/sonarr"
  ensure_dir "$MEDIA_MEDIA_DIR/movies"
  ensure_dir "$MEDIA_MEDIA_DIR/tv"
  ensure_dir "$MEDIA_DOWNLOADS_DIR"
}

# This function determines whether the docker compose plugin or legacy binary should be used.
determine_compose_cmd() {
  ensure_command docker
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
    return
  fi
  fail "Neither 'docker compose' nor 'docker-compose' is available."
}

# This function runs docker compose with the loaded env file and compose file while logging the invocation.
run_compose() {
  local args=("$@")
  log "Running: ${COMPOSE_CMD[*]} --env-file $ENV_FILE -f $COMPOSE_FILE ${args[*]}"
  "${COMPOSE_CMD[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "${args[@]}"
}

# This function retries a command a few times to smooth over transient network hiccups.
run_with_retries() {
  local description="$1"
  shift
  local attempt=1
  while ((attempt <= MAX_RETRIES)); do
    if "$@"; then
      return 0
    fi
    log "Attempt ${attempt}/${MAX_RETRIES} failed while ${description}; retrying after ${RETRY_DELAY_SECONDS}s..."
    sleep $((RETRY_DELAY_SECONDS * attempt))
    ((attempt++))
  done
  fail "Unable to complete: ${description}"
}

# This function pulls docker images ahead of time to ensure `docker compose up` never needs extra user commands.
prepull_images() {
  run_with_retries "pulling docker images" run_compose pull
}

# This function gathers the TCP ports that must be opened for the stack based on configuration and sensible defaults.
collect_firewall_ports() {
  FIREWALL_PORTS=()
  local plex_port="${PLEX_HTTP_PORT:-32400}"
  local radarr_port="${RADARR_PORT:-7878}"
  local sonarr_port="${SONARR_PORT:-8989}"
  local value
  FIREWALL_PORTS+=("$plex_port" "$radarr_port" "$sonarr_port")
  if [[ -n "${MEDIA_EXTRA_TCP_PORTS:-}" ]]; then
    IFS=',' read -r -a extra_ports <<<"$MEDIA_EXTRA_TCP_PORTS"
    for value in "${extra_ports[@]}"; do
      value="${value//[[:space:]]/}"
      [[ -n "$value" ]] && FIREWALL_PORTS+=("$value")
    done
  fi
}

# This function ensures ufw is enabled and configured to allow each required TCP port for the media stack.
configure_firewall() {
  collect_firewall_ports
  if ((${#FIREWALL_PORTS[@]} == 0)); then
    log "No firewall ports requested; skipping firewall configuration."
    return
  fi
  ensure_command ufw
  initialize_state_store
  local status_line
  status_line="$(run_privileged ufw status | head -n 1 2>/dev/null || true)"
  if [[ "$status_line" == "Status: inactive" ]]; then
    log "Enabling ufw firewall..."
    run_privileged ufw --force enable >/dev/null
  fi
  local port
  for port in "${FIREWALL_PORTS[@]}"; do
    if [[ -z "$port" ]]; then
      continue
    fi
    local rule="${port}/tcp"
    if run_privileged ufw status | grep -qw "$rule"; then
      log "Firewall rule for $rule already exists; skipping."
    else
      log "Adding firewall rule to allow $rule"
      run_privileged ufw allow "$rule" comment "media-stack-${port}" >/dev/null
      record_firewall_rule "$rule"
    fi
  done
}

# This function removes every firewall rule previously recorded during deploy so rollback leaves no trace.
remove_firewall_rules() {
  if [[ ! -f "$FIREWALL_STATE_FILE" ]]; then
    log "No recorded firewall rules to remove."
    return
  fi
  ensure_command ufw
  while IFS= read -r rule; do
    [[ -z "$rule" ]] && continue
    if run_privileged ufw status | grep -qw "$rule"; then
      log "Removing firewall rule for $rule"
      run_privileged ufw --force delete allow "$rule" >/dev/null || log "Failed to remove firewall rule $rule; continuing."
    fi
  done <"$FIREWALL_STATE_FILE"
  clear_firewall_state
}

# This function runs docker compose up after prerequisites are installed, directories prepared, and firewall configured.
deploy_stack() {
  local extra_up_args=("$@")
  prepare_directories
  configure_firewall
  prepull_images
  local up_args
  if ((${#extra_up_args[@]} > 0)); then
    up_args=("up" "${extra_up_args[@]}")
  else
    up_args=("up" "-d")
  fi
  run_compose "${up_args[@]}"
  verify_stack
}

# This function provides a quick health check by showing the current docker compose status after deployment.
verify_stack() {
  log "Verifying container status..."
  run_compose ps
}

# This function captures the deploy prerequisites shared by every command to avoid repetition.
bootstrap_stack() {
  local allow_env_bootstrap="$1"
  ensure_env_file "$allow_env_bootstrap"
  load_env
  ensure_required_env_vars
  initialize_state_store
  detect_package_manager
  install_prerequisites
  determine_compose_cmd
}

# This function reverses everything performed during deployment, including containers, data, and firewall rules.
rollback_stack() {
  log "Stopping and removing containers, networks, images, and volumes..."
  run_compose down --volumes --remove-orphans --rmi all
  log "Removing persistent data directories..."
  remove_dir "$MEDIA_CONFIG_DIR"
  remove_dir "$MEDIA_DOWNLOADS_DIR"
  remove_dir "$MEDIA_MEDIA_DIR/movies"
  remove_dir "$MEDIA_MEDIA_DIR/tv"
  log "Removing firewall rules..."
  remove_firewall_rules
  log "Rollback complete."
}

# This function orchestrates the entire script lifecycle, routing subcommands to their implementations.
main() {
  determine_privileged_runner
  local resolved_compose
  resolved_compose="$(resolve_path "$COMPOSE_FILE_INPUT")"
  COMPOSE_FILE="$resolved_compose"
  local resolved_env
  resolved_env="$(resolve_path "$ENV_FILE_INPUT")"
  ENV_FILE="$resolved_env"
  local resolved_template
  resolved_template="$(resolve_path "$ENV_TEMPLATE_FILE_INPUT")"
  ENV_TEMPLATE_FILE="$resolved_template"
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
      bootstrap_stack "true"
      deploy_stack "$@"
      ;;
    rollback)
      bootstrap_stack "false"
      rollback_stack
      ;;
    *)
      bootstrap_stack "true"
      if [[ "$action" == "up" ]]; then
        prepare_directories
      fi
      run_compose "$action" "$@"
      ;;
  esac
}

# This invocation hands control to the main orchestrator with every CLI argument preserved.
main "$@"
