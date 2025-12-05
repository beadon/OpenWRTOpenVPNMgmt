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

FROM openwrt/rootfs:x86-64-openwrt-23.05

# SSH public key injected at build time
ARG SSH_PUBLIC_KEY

# Run setup if needed (for newer OpenWrt versions)
RUN [ -f ./setup.sh ] && ./setup.sh || true

# Update package lists and install minimal packages for SSH access
RUN opkg update && opkg install \
    openssh-server \
    openssh-sftp-server \
    && rm -rf /var/opkg-lists/*

# Configure SSH
RUN mkdir -p /etc/ssh /root/.ssh && \
    chmod 700 /root/.ssh && \
    ssh-keygen -A

# Add the SSH public key for passwordless access
RUN echo "$SSH_PUBLIC_KEY" > /root/.ssh/authorized_keys && \
    chmod 600 /root/.ssh/authorized_keys

# Set root password to 'admin'
RUN echo 'root:admin' | chpasswd

# Expose SSH port
EXPOSE 22

# Use init as PID 1 for proper service management
CMD ["/sbin/init"]
