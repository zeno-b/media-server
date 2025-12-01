#!/usr/bin/env bash

# This directive enforces strict error handling, halting on undefined variables, command errors, or broken pipelines.
set -euo pipefail
set -o errtrace
# This directive standardizes word splitting to eliminate surprising whitespace behavior.
IFS=$'\n\t'
# This trap routes every unexpected error through the dedicated handler so failures always log contextual information.
trap 'handle_error $? $LINENO' ERR

# This variable stores the directory that contains this script so relative paths remain stable no matter where we run from.
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# This variable defines where docker-compose.yml is expected to live by default unless COMPOSE_FILE overrides it.
readonly DEFAULT_COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
# This variable captures a user override for compose configuration, falling back to the default path when unset.
readonly COMPOSE_FILE_INPUT="${COMPOSE_FILE:-$DEFAULT_COMPOSE_FILE}"
# This variable defines the default .env path so configuration lives alongside the script when not overridden.
readonly DEFAULT_ENV_FILE="${SCRIPT_DIR}/.env"
# This variable captures a user-provided env file location while defaulting to the local .env file.
readonly ENV_FILE_INPUT="${MEDIA_STACK_ENV:-$DEFAULT_ENV_FILE}"
# This variable points to the template env file so the script can bootstrap configuration automatically.
readonly ENV_TEMPLATE_FILE_INPUT="${SCRIPT_DIR}/.env.example"
# This variable records the directory used to store deployment state artifacts (e.g., firewall rules) for safe rollback.
readonly STATE_DIR="${SCRIPT_DIR}/.media_stack_state"
# This variable tracks the file that lists firewall rules added by the deploy workflow so rollback knows what to remove.
readonly FIREWALL_STATE_FILE="${STATE_DIR}/firewall_rules"
# This variable defines how many attempts should be made when retrying transient operations (e.g., image pulls).
readonly MAX_RETRIES=3
# This variable defines the base delay (in seconds) between retries to avoid hammering external services.
readonly RETRY_DELAY_SECONDS=5
# This variable defines which docker compose release to download when repository packages are unavailable.
readonly COMPOSE_FALLBACK_VERSION="${COMPOSE_FALLBACK_VERSION:-v2.29.7}"
# These arrays provide centralized declarations for validation and directory preparation.
readonly -a REQUIRED_ENV_VARS=(PUID PGID TZ MEDIA_CONFIG_DIR MEDIA_MEDIA_DIR MEDIA_DOWNLOADS_DIR RADARR_PORT SONARR_PORT PROWLARR_PORT JACKETT_PORT TRANSMISSION_WEB_PORT TRANSMISSION_RPC_PORT TRANSMISSION_PEER_PORT MEDIA_LOCAL_NETWORK_CIDR)
readonly -a REQUIRED_PORT_VARS=(RADARR_PORT SONARR_PORT PROWLARR_PORT JACKETT_PORT TRANSMISSION_WEB_PORT TRANSMISSION_RPC_PORT TRANSMISSION_PEER_PORT)
readonly -a SERVICE_CONFIG_DIRS=(plex radarr sonarr prowlarr jackett transmission)
# This variable indicates which package manager should be used; currently only apt is supported.
PACKAGE_MANAGER=""
# This flag tracks whether the package index has already been refreshed to avoid redundant update calls.
PACKAGE_INDEX_REFRESHED=false
# This variable caches which privileged runner to use; it is empty when running as root and "sudo" otherwise.
SUDO_BIN=""
# This array captures the resolved docker compose command variant (plugin or legacy binary).
COMPOSE_CMD=()
# This array stores firewall rules as proto|port|source entries so we can reproduce them during rollback.
FIREWALL_RULES=()

# This function prints informational messages with a consistent prefix for easier log scanning.
log() {
  printf '[media-stack][info] %s\n' "$*"
}

# This function highlights key phase transitions to keep console output easy to follow.
log_step() {
  printf '\n[media-stack][step] %s\n' "$*"
}

# This function emits warning messages while keeping the format consistent with other logs.
log_warn() {
  printf '[media-stack][warn] %s\n' "$*" >&2
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
  MEDIA_LOCAL_NETWORK_CIDR CIDR block that should be allowed through the firewall (e.g. 192.168.1.0/24).
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

# This function checks whether the requested apt package exists in the configured repositories.
apt_package_available() {
  local package="$1"
  if [[ -z "$package" ]]; then
    fail "apt_package_available requires a package name."
  fi
  detect_package_manager
  if [[ "$PACKAGE_MANAGER" != "apt" ]]; then
    return 1
  fi
  refresh_package_index_once
  local candidate
  candidate="$(apt-cache policy "$package" 2>/dev/null | awk -F': ' '/Candidate:/ {print $2; exit}' || true)"
  if [[ -z "$candidate" || "$candidate" == "(none)" ]]; then
    return 1
  fi
  return 0
}

# This function determines the correct docker compose binary architecture identifier.
detect_compose_arch() {
  local kernel_arch
  kernel_arch="$(uname -m)"
  case "$kernel_arch" in
    x86_64|amd64)
      printf 'x86_64\n'
      ;;
    arm64|aarch64)
      printf 'aarch64\n'
      ;;
    armv7l|armv7)
      printf 'armv7\n'
      ;;
    *)
      fail "Unsupported architecture '${kernel_arch}' for docker compose fallback installation."
      ;;
  esac
}

# This function downloads and installs the docker compose CLI plugin directly from the upstream release artifacts.
install_compose_from_upstream_release() {
  ensure_command curl
  local arch
  arch="$(detect_compose_arch)"
  local version="$COMPOSE_FALLBACK_VERSION"
  local plugin_dir="/usr/local/lib/docker/cli-plugins"
  local destination="${plugin_dir}/docker-compose"
  local url="https://github.com/docker/compose/releases/download/${version}/docker-compose-linux-${arch}"
  log "Installing docker compose plugin (${version}, ${arch}) from upstream release..."
  run_privileged mkdir -p "$plugin_dir" || return 1
  run_privileged curl -fsSL "$url" -o "$destination" || return 1
  run_privileged chmod +x "$destination" || return 1
}

# This function ensures either the docker compose CLI plugin or the legacy docker-compose binary is installed.
install_docker_compose_support() {
  if docker compose version >/dev/null 2>&1; then
    return
  fi
  detect_package_manager
  local plugin_attempted=false
  local plugin_installed=false
  case "$PACKAGE_MANAGER" in
    apt)
      if apt_package_available "docker-compose-plugin"; then
        plugin_attempted=true
        install_packages_if_missing docker-compose-plugin
        plugin_installed=true
      else
        plugin_attempted=true
        if install_compose_from_upstream_release; then
          plugin_installed=true
        else
          log_warn "Failed to install docker compose plugin from upstream release."
        fi
      fi
      ;;
    *)
      plugin_attempted=true
      if install_compose_from_upstream_release; then
        plugin_installed=true
      else
        log_warn "Failed to install docker compose plugin from upstream release."
      fi
      ;;
  esac
  if docker compose version >/dev/null 2>&1; then
    return
  fi
  if [[ "$plugin_installed" == "true" ]]; then
    log_warn "docker compose plugin appears installed but command is unavailable; attempting legacy docker-compose."
  elif [[ "$plugin_attempted" == "true" ]]; then
    log_warn "docker compose plugin installation failed; attempting legacy docker-compose."
  else
    log_warn "docker compose plugin not attempted; attempting legacy docker-compose."
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    return
  fi
  case "$PACKAGE_MANAGER" in
    apt)
      if apt_package_available "docker-compose"; then
        install_packages_if_missing docker-compose
        return
      fi
      ;;
  esac
  fail "Unable to install docker compose plugin or legacy docker-compose binary."
}

# This function installs every prerequisite required for the media stack, including Docker, docker compose, and ufw.
install_prerequisites() {
  local base_packages=(ca-certificates curl gnupg lsb-release ufw software-properties-common)
  install_packages_if_missing "${base_packages[@]}"
  install_packages_if_missing docker.io
  install_docker_compose_support
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

# This function appends a firewall rule entry if it is not already present in the staging array.
append_firewall_rule() {
  local proto="$1"
  local port="$2"
  local source="${3:-any}"
  if [[ -z "$port" ]]; then
    return
  fi
  local entry="${proto}|${port}|${source}"
  local existing
  for existing in "${FIREWALL_RULES[@]}"; do
    if [[ "$existing" == "$entry" ]]; then
      return
    fi
  done
  FIREWALL_RULES+=("$entry")
}

# This function checks whether a ufw rule already exists for the given protocol, port, and source.
firewall_rule_exists() {
  local proto="$1"
  local port="$2"
  local source="${3:-any}"
  local status
  status="$(run_privileged ufw status 2>/dev/null || true)"
  if [[ -z "$status" ]]; then
    return 1
  fi
  if [[ "$source" == "any" ]]; then
    if grep -Fq "${port}/${proto}" <<<"$status"; then
      return 0
    fi
    return 1
  fi
  while IFS= read -r line; do
    if [[ "$line" == *"${port}/${proto}"* && "$line" == *"$source"* ]]; then
      return 0
    fi
  done <<<"$status"
  return 1
}

# This function applies a firewall rule (if missing) and records it for rollback.
apply_firewall_rule() {
  local proto="$1"
  local port="$2"
  local source="${3:-any}"
  local pretty_source="${source:-any}"
  if firewall_rule_exists "$proto" "$port" "$source"; then
    log "Firewall rule for ${port}/${proto} from ${pretty_source} already exists; skipping."
    return
  fi
  log "Adding firewall rule to allow ${port}/${proto} from ${pretty_source}"
  local comment="media-stack-${port}-${proto}"
  if [[ "$source" == "any" ]]; then
    run_privileged ufw allow "$port/$proto" comment "$comment" >/dev/null
  else
    run_privileged ufw allow from "$source" to any port "$port" proto "$proto" comment "$comment" >/dev/null
  fi
  record_firewall_rule "${proto}|${port}|${source}"
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
  local var
  for var in "${REQUIRED_ENV_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
      missing+=("$var")
    fi
  done
  if ((${#missing[@]} > 0)); then
    fail "Missing required variable(s) in $ENV_FILE: ${missing[*]}"
  fi
  validate_port_values
  validate_user_group_ids
}

# This function ensures every declared port-like value is numeric and within the valid TCP/UDP range.
validate_port_values() {
  local invalid=()
  local var
  local value
  for var in "${REQUIRED_PORT_VARS[@]}"; do
    value="${!var:-}"
    if ! is_valid_port "$value"; then
      invalid+=("${var}=${value:-<empty>}")
    fi
  done
  if ((${#invalid[@]} > 0)); then
    fail "Invalid port value(s) detected: ${invalid[*]}. Expected integers between 1 and 65535."
  fi
}

# This helper validates a single port value according to basic TCP/UDP constraints.
is_valid_port() {
  local candidate="$1"
  [[ "$candidate" =~ ^[0-9]+$ ]] || return 1
  local -i port="$candidate"
  ((port >= 1 && port <= 65535)) || return 1
  return 0
}

validate_user_group_ids() {
  local invalid=()
  if ! is_positive_integer "${PUID:-}"; then
    invalid+=("PUID=${PUID:-<empty>}")
  fi
  if ! is_positive_integer "${PGID:-}"; then
    invalid+=("PGID=${PGID:-<empty>}")
  fi
  if ((${#invalid[@]} > 0)); then
    fail "Invalid user/group ID value(s): ${invalid[*]}. Provide numeric IDs such as 1000."
  fi
}

is_positive_integer() {
  local candidate="$1"
  [[ "$candidate" =~ ^[0-9]+$ ]] || return 1
  return 0
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
  ensure_dir_ownership "$resolved"
  log "Ensured directory: $resolved"
}

ensure_dir_ownership() {
  local path="$1"
  if [[ -z "${PUID:-}" || -z "${PGID:-}" ]]; then
    return
  fi
  [[ -e "$path" ]] || return
  local desired="${PUID}:${PGID}"
  local current
  current="$(stat -c '%u:%g' "$path" 2>/dev/null || true)"
  if [[ "$current" == "$desired" ]]; then
    return
  fi
  run_privileged chown "$desired" "$path"
  log "Aligned ownership (${desired}) for $path"
}

# This function batches directory creation to reduce boilerplate and improve readability.
ensure_dirs() {
  local path
  for path in "$@"; do
    [[ -z "$path" ]] && continue
    ensure_dir "$path"
  done
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

# This function prepares the filesystem tree expected by every service prior to running docker compose.
prepare_directories() {
  local config_paths=()
  local name
  for name in "${SERVICE_CONFIG_DIRS[@]}"; do
    config_paths+=("$MEDIA_CONFIG_DIR/$name")
  done
  ensure_dirs "${config_paths[@]}"
  ensure_dirs \
    "$MEDIA_MEDIA_DIR/movies" \
    "$MEDIA_MEDIA_DIR/tv" \
    "$MEDIA_DOWNLOADS_DIR" \
    "$MEDIA_DOWNLOADS_DIR/watch" \
    "$MEDIA_DOWNLOADS_DIR/incomplete"
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

# This function gathers the firewall rules required for every service so ufw can be configured consistently.
collect_firewall_rules() {
  FIREWALL_RULES=()
  local local_cidr="${MEDIA_LOCAL_NETWORK_CIDR:-any}"
  local -a tcp_ports=(
    "${PLEX_HTTP_PORT:-32400}"
    "${RADARR_PORT:-7878}"
    "${SONARR_PORT:-8989}"
    "${PROWLARR_PORT:-9696}"
    "${JACKETT_PORT:-9117}"
    "${TRANSMISSION_WEB_PORT:-9091}"
    "${TRANSMISSION_RPC_PORT:-9091}"
    "${TRANSMISSION_PEER_PORT:-51413}"
  )
  local port
  for port in "${tcp_ports[@]}"; do
    append_firewall_rule "tcp" "$port" "$local_cidr"
  done
  append_firewall_rule "udp" "${TRANSMISSION_PEER_PORT:-51413}" "$local_cidr"
  if [[ -n "${MEDIA_EXTRA_TCP_PORTS:-}" ]]; then
    local -a extra_ports=()
    IFS=',' read -r -a extra_ports <<<"$MEDIA_EXTRA_TCP_PORTS"
    local value
    for value in "${extra_ports[@]}"; do
      value="${value//[[:space:]]/}"
      [[ -n "$value" ]] && append_firewall_rule "tcp" "$value" "$local_cidr"
    done
  fi
}

# This function ensures ufw is enabled and configured to allow each required rule for the media stack.
configure_firewall() {
  collect_firewall_rules
  if ((${#FIREWALL_RULES[@]} == 0)); then
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
  local entry
  for entry in "${FIREWALL_RULES[@]}"; do
    IFS='|' read -r proto port source <<<"$entry"
    [[ -z "$port" ]] && continue
    apply_firewall_rule "$proto" "$port" "$source"
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
    local proto
    local port
    local source
    if [[ "$rule" == *"|"* ]]; then
      IFS='|' read -r proto port source <<<"$rule"
    else
      proto="${rule##*/}"
      port="${rule%/*}"
      source="any"
    fi
    [[ -z "$proto" || -z "$port" ]] && continue
    local pretty_source="${source:-any}"
    log "Removing firewall rule for ${port}/${proto} from ${pretty_source}"
    if [[ "$source" == "any" ]]; then
      run_privileged ufw --force delete allow "$port/$proto" >/dev/null || log_warn "Failed to remove firewall rule ${port}/${proto}; continuing."
    else
      run_privileged ufw --force delete allow from "$source" to any port "$port" proto "$proto" >/dev/null || log_warn "Failed to remove firewall rule ${port}/${proto} from ${pretty_source}; continuing."
    fi
  done <"$FIREWALL_STATE_FILE"
  clear_firewall_state
}

# This function runs docker compose up after prerequisites are installed, directories prepared, and firewall configured.
deploy_stack() {
  local extra_up_args=("$@")
  log_step "Preparing persistent directories"
  prepare_directories
  log_step "Configuring firewall rules"
  configure_firewall
  log_step "Pre-pulling container images"
  prepull_images
  local up_args
  if ((${#extra_up_args[@]} > 0)); then
    up_args=("up" "${extra_up_args[@]}")
  else
    up_args=("up" "-d")
  fi
  log_step "Starting docker compose services"
  run_compose "${up_args[@]}"
  verify_stack
}

# This function provides a quick health check by showing the current docker compose status after deployment.
verify_stack() {
  log_step "Verifying container status"
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
      action="help"
      ;;
    deploy|--deploy|-deploy)
      action="deploy"
      ;;
    rollback|--rollback|-rollback)
      action="rollback"
      ;;
  esac
  case "$action" in
    help)
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
