# OpenWrt Test Environment for OpenVPN Management Script
# Clean OpenWrt rootfs - script installs its own dependencies
#
# Build:
#   docker build --build-arg SSH_PUBLIC_KEY="$(cat ~/.ssh/id_rsa.pub)" -t openwrt-ovpn-test ./docker
#
# Run (interactive shell - keeps container alive):
#   docker run -it --name openwrt-test -p 2222:22 openwrt-ovpn-test
#
# Connect (from separate terminal):
#   ssh root@localhost -p 2222
#
# Stop:
#   Exit the interactive shell (Ctrl+D or 'exit') to stop the container

FROM openwrt/rootfs:x86-64-openwrt-24.10

# SSH public key injected at build time
ARG SSH_PUBLIC_KEY

# Run setup.sh to initialize filesystem
RUN [ -f /setup.sh ] && /setup.sh || true

# Create /var/lock for opkg (required per OpenWRT Docker docs)
RUN mkdir -p /var/lock

# Update package lists
RUN opkg update && rm -rf /var/opkg-lists/*

# Configure SSH authorized key
RUN mkdir -p /etc/dropbear /root/.ssh && \
    chmod 700 /root/.ssh && \
    echo "$SSH_PUBLIC_KEY" > /etc/dropbear/authorized_keys && \
    chmod 600 /etc/dropbear/authorized_keys

# Expose SSH port
EXPOSE 22

# Use init as PID 1 for proper service management
CMD ["/sbin/init"]
