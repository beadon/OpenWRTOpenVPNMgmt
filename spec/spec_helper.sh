# ShellSpec spec_helper.sh
# Common setup for all tests

# shellcheck shell=sh

# Docker container name for integration tests
CONTAINER_NAME="openwrt-test"
CONTAINER_IMAGE="openwrt-ovpn-test"

# Path to script under test
SCRIPT_PATH="openvpn_server_management.sh"

# Timeout for Docker commands (seconds)
DOCKER_TIMEOUT=60

# Helper: Check if Docker container is running
container_running() {
    docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# Helper: Start Docker container if not running
start_container() {
    if ! container_running; then
        docker run -d --name "$CONTAINER_NAME" "$CONTAINER_IMAGE" /sbin/init >/dev/null 2>&1
        # Wait for container to be ready
        sleep 2
    fi
}

# Helper: Stop and remove Docker container
stop_container() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

# Helper: Execute command in container with timeout
docker_exec() {
    timeout "$DOCKER_TIMEOUT" docker exec "$CONTAINER_NAME" "$@"
}

# Helper: Copy script to container
copy_script_to_container() {
    docker cp "$SCRIPT_PATH" "${CONTAINER_NAME}:/root/"
    docker_exec chmod +x "/root/$SCRIPT_PATH"
}

# Helper: Run script with menu input
run_menu_option() {
    local option="$1"
    shift
    # Send option followed by any additional inputs, then exit (19)
    printf '%s\n' "$option" "$@" "19" | docker_exec /root/"$SCRIPT_PATH"
}

# Helper: Extract error handling functions for unit testing
# Sources only the function definitions without running the main script
extract_functions() {
    # Extract lines from ERROR HANDLING FUNCTIONS section
    sed -n '/^# Temp file tracking/,/^################################################################################$/p' "$SCRIPT_PATH" | head -n -1
}
