# OpenWRT OpenVPN Management 
Openwrt VPN setup and management script, making management of Open VPN via CLI much simpler.

The All-in-One OpenVPN Management Script
Tired of managing keys, ovpn files and all different parts piecemeal ? Use this script on the CLI to manage it all.


Assuming you have installed wget...
```
opkg update
opkg install wget
```
Then if you are SSSH'd into OpenWRT now, grab then run it like this:
```
wget https://raw.githubusercontent.com/beadon/OpenWRTOpenVPNMgmt/refs/heads/main/openvpn_server_management.sh
chmod 775 openvpn_server_management.sh
./openvpn_server_management.sh
```

# First-Time Setup Guide

This guide assumes you're starting from scratch with nothing installed. Follow these steps to get a fully functional OpenVPN server with your first client configuration.

## Prerequisites

1. **Install required packages:**
   ```bash
   opkg update
   opkg install openvpn-openssl wget
   ```

2. **Download and run the script:**
   ```bash
   wget https://raw.githubusercontent.com/beadon/OpenWRTOpenVPNMgmt/refs/heads/main/openvpn_server_management.sh
   chmod 775 openvpn_server_management.sh
   ./openvpn_server_management.sh
   ```

   The script will auto-create the default "server" instance on first run.

## Step-by-Step Setup

### Step 1: Install LuCI Web Interface (Optional but Recommended)

**Menu Option: 13**

```
13) Install LuCI OpenVPN web interface
Continue with installation? (yes/no): yes
```

This installs `luci-app-openvpn` which provides:
- Web-based management interface
- Instance control (start/stop/restart)
- Configuration file editing
- Status monitoring

**Access:** Web Interface → Services → OpenVPN (or System → OpenVPN)

**Note:** Changes made in LuCI and this script are synchronized via UCI.

### Step 2: Install and Initialize EasyRSA

**Menu Option: 12**

```
12) Install and initialize EasyRSA for OpenVPN
```

This will:
- Initialize the PKI (Public Key Infrastructure)
- Generate Diffie-Hellman parameters
- Create the Certificate Authority (CA)
- Generate server certificate and keys
- Create TLS-Crypt key

**Important:** This step takes several minutes due to cryptographic key generation.

### Step 3: Auto-Detect Server Settings

**Menu Option: 0**

```
0) Auto-Detect server settings
```

This automatically detects:
- **Network Configuration:** Port (1194), Protocol (UDP)
- **Server Address:** DDNS hostname or WAN IP
- **IPv4 Settings:** VPN subnet, DNS server, domain
- **IPv6 Settings:** Prefix delegation from ISP, available subnets

Review the detected settings. The script will use these for configuration generation.

**DDNS Support:**

The auto-detect feature will automatically detect your DDNS hostname if configured using OpenWrt's standard DDNS setup. This is recommended for dynamic IP addresses so your VPN clients can always connect using a stable hostname (e.g., `myvpn.dyndns.org`) instead of a changing IP address.

**To set up DDNS before running auto-detect:**
1. Follow the official OpenWrt DDNS guide: https://openwrt.org/docs/guide-user/services/ddns/client
2. Configure your DDNS service provider in LuCI or UCI
3. Verify DDNS is working: `nslookup your-hostname.dyndns.org`
4. Run this script's auto-detect (Option 0) - it will automatically use your DDNS hostname

If DDNS is not configured, the script will fall back to using your current WAN IP address.

### Step 4: Configure IPv6 (Optional)

**Menu Option: 3**

```
3) Toggle IPv6 support (Currently: yes)
Enable IPv6 support? (yes/no): yes

Select IPv6 mode:
  1) Static pool (recommended) - Simple, uses server-ipv6 directive
  2) DHCPv6-PD (advanced) - Tracked leases, requires odhcpd configuration

Select mode (1-2): 1

Enter IPv6 subnet: 2001:db8:1234:1194::/64
Enter max clients limit (default 253): 100
```

**IPv6 Subnet Options:**
- **Globally routable:** Use a /64 from your ISP's delegation (detected in Step 3)
- **Private ULA:** Generate at https://unique-local-ipv6.com/

### Step 5: Generate Server Configuration

**Menu Option: 1**

```
1) Generate/Update server.conf
Continue and overwrite? (yes/no): yes
View the generated configuration? (y/n): y
```

This creates `/etc/openvpn/server.conf` with:
- Network settings (port, protocol, subnet)
- IPv4 and IPv6 configuration (if enabled)
- Certificate paths
- Client push routes and DNS
- Security settings

**UCI Integration:** Automatically updates `/etc/config/openvpn` with the instance configuration.

**Autostart Configuration:** The script automatically enables the OpenVPN service to start on router boot by running `/etc/init.d/openvpn enable`. This ensures your VPN server starts automatically after power cycles or reboots.

### Step 6: Configure Firewall

**Menu Option: 15**

```
15) Configure VPN firewall access
Continue with firewall configuration? (yes/no): yes
Restart firewall to apply changes? (y/n): y
```

This will:
- Add VPN interface (tun+) to LAN zone (gives VPN clients LAN access)
- Allow OpenVPN port on WAN (IPv4 & IPv6)
- Enable IPv6 forwarding (if IPv6 is enabled)

**Verify Firewall:**

```
14) Check firewall configuration
```

Confirms :
- VPN interface in LAN zone
- OpenVPN port open on WAN

### Step 7: Restart OpenVPN

From Step 5, when prompted:

```
Restart OpenVPN instance 'server' to apply changes? (y/n): y
```

Or manually:
```bash
/etc/init.d/openvpn restart server
```

### Step 8: Create Your First Client Certificate

**Menu Option: 4**

```
4) Create new client certificate
Enter client name: username.laptop
Generate .ovpn config file? (y/n): y
```

**Client Naming:**
Keys are issued per-user per-device.  It is recommended that you choose the name of the device and the owner of the name in in the config.  Some OpenVPN clients permit the user to share the client configuration with all users of their system, there's no control you have over this as a server once the key is issued.

Advise your users how to install the keys on their system based on the naming scheme you select.  This installation of the .OVPN files on the client machine is an exercise for you or your user.

Know that by default the OpenVPN server will only allow one connection per client device at a time, this means that if you generate a single client ovpn file and place it on 2 devices, only one of these will be able to be connected at a time.  If the second client connects with the same key the first client will be kicked off.  This may be desirable behavior to keep the number of clients to a minimum, or it could be a hassle since more keys are required to support a per-user-per-device.  Either way, this script makes managing this easy.

**Security**
This naming scheme can be made more GDPR compliant by using a userID number instead of the user's name.  This way the user's real name is not used in any provisioning systems.  However, for most things this is an unnecessary complexity.

This can be arranged any way you like, consider a naming scheme like:
```<username>.<device>```

- Examples: `bill.laptop`, `bill.phone`, `john.macbook`
- Each client needs a unique certificate

**Files Created:**
- Certificate: `/etc/easy-rsa/pki/issued/bill.laptop.crt`
- Private key: `/etc/easy-rsa/pki/private/bill.laptop.key`
- TLS-Crypt key: `/etc/easy-rsa/pki/private/bill.laptop.pem`
- Client config: `/root/ovpn_config_out/bill.laptop.ovpn`

### Step 9: Download Client Configuration

The `.ovpn` file is located at: `/root/ovpn_config_out/bill.laptop.ovpn`

**Transfer the .ovpn file(s) from the router to your device using:**

**SCP (from your computer):**
```bash
scp root@192.168.1.1:/root/ovpn_config_out/bill.laptop.ovpn ~/Downloads/
```

**Or via LuCI Web Interface:**
NOTE: file browser is installable as ```opkg install luci-app-filemanager```

1. Navigate to System → File Browser (if available)

### Step 10: Connect Your Client

**Windows/Mac/Linux:**
1. Install OpenVPN client
2. Import `bill.laptop.ovpn`
3. Connect

**Android/iOS:**
NOTE: the re-use of the laptop key here will cause connection problems for the user, issue them a second client key in line with your key issuing naming convention (see above).

1. Install OpenVPN Connect app (from the Play Store, or App Store)
2. Import `bill.laptop.ovpn`
3. Connect

**Verify Connection:**
```bash
# On client device:
ping 10.8.0.1           # Ping VPN server
ping6 google.com        # Test IPv6 (if enabled)
curl -4 ifconfig.co     # Check IPv4 address
curl -6 ifconfig.co     # Check IPv6 address (if enabled)
```

One the client device (the laptop or mobile device) open a browser while the VPN connection is established to check that this reflect's the OpenVPN server's IP [https://www.whatismyip.com/](https://www.whatismyip.com/)

# FEATURES

## UCI Management Integration
  - Script now fully integrates with OpenWrt's UCI configuration system
  - All instances are stored in /etc/config/openvpn
  - Compatible with luci-app-openvpn - changes sync between both interfaces
  - Auto-creates default "server" instance on first run

  UCI Configuration Example

```
  # View all instances
  uci show openvpn

  # Example output:
  # openvpn.server=openvpn
  # openvpn.server.enabled='1'
  # openvpn.server.config='/etc/openvpn/server.conf'
```

### Instance Selection (Menu options i and l)
  - Option i: Select/Create OpenVPN instance
    - Lists all existing instances with status (enabled/disabled, running/stopped)
    - Create new instances (validated: >3 chars, alphanumeric + underscore)
    - Switch between instances during session
  - Option l: List all OpenVPN instances
    - Shows instance status, config file path, and running state

## LuCI Integration
  - Install luci-app-openvpn with one command
  - Automatic opkg update and package installation
  - Changes made in LuCI web interface appear in this script and vice versa


## OpenVPN Monitoring
  - Lists all available instances
  - Select specific instance to monitor OR monitor all instances
  - Sends SIGUSR2 to correct instance-specific process
  - Shows per-instance network status and client connections

## Instance-Aware Operations
  - All operations now use the selected instance
  - Config files: /etc/openvpn/${INSTANCE_NAME}.conf
  - Process control: /etc/init.d/openvpn restart ${INSTANCE_NAME}
  - Menu shows: "Currently managing: [server]"

  File Structure
```
  /etc/config/openvpn          # UCI configuration (shared with LuCI)
  /etc/openvpn/
    ├── server.conf            # Default server instance config
    ├── office_vpn.conf        # Example: additional instance
    └── *.conf                 # Instance configs
```

## Quick Reference - Common Operations

### Monitor VPN Status

**Menu Option: 16**

```
16) Monitor VPN address usage (IPv4 & IPv6)
Select instance to monitor: 1
```

Shows:
- Connected clients
- IPv4/IPv6 addresses in use
- Bandwidth usage per client
- Connection times

### Create Additional Clients

```
**Menu Option: 4** (Create certificate)
**Menu Option: 11** (Generate single .ovpn file)
```

### Manage Multiple Server Instances

```
**Menu Option: i** - Select/Create instance
**Menu Option: l** - List all instances
```

Example:
```
i) Select/Create OpenVPN instance
Select option: n
Enter new instance name: office_vpn
```

### Revoke a Client Certificate

**Menu Option: 6**

```
6) Revoke client certificate
Enter client name to revoke: laptop
Are you sure? (yes/no): yes
Restart OpenVPN daemon to apply changes? (y/n): y
```

### Check Certificate Expiration

**Menu Option: 7**

```
7) Check certificate expiration
```

Shows expiration status for all certificates.

## Troubleshooting

### IPv6 Not Working

1. **Verify IPv6 is enabled:**
   ```bash
   cat /proc/sys/net/ipv6/conf/all/forwarding
   # Should output: 1
   ```

2. **Check tunnel has IPv6:**
   ```bash
   ip -6 addr show tun0
   ```

3. **Test connectivity:**
   ```bash
   ping6 google.com
   ```

4. **Check firewall logs:**
   ```bash
   logread | grep -i ipv6
   ```

### Clients Can't Connect

1. **Check firewall:**
   - Menu Option 14 (Check firewall configuration)
   - Verify OpenVPN port is open

2. **Check OpenVPN is running:**
   ```bash
   /etc/init.d/openvpn status
   ```

3. **View logs:**
   ```bash
   logread | grep openvpn
   cat /var/log/openvpn.log
   ```

### OpenVPN Doesn't Start After Reboot

1. **Check if service is enabled for autostart:**
   ```bash
   /etc/init.d/openvpn enabled
   echo $?
   # Should return: 0 (enabled) or 1 (disabled)
   ```

2. **Enable autostart if disabled:**
   ```bash
   /etc/init.d/openvpn enable
   ```

3. **Check UCI instance is enabled:**
   ```bash
   uci get openvpn.server.enabled
   # Should return: 1
   ```

4. **Verify both are configured:**
   ```bash
   # Check init.d
   ls -l /etc/rc.d/S*openvpn*
   # Should show: /etc/rc.d/S90openvpn -> ../init.d/openvpn

   # Check UCI
   uci show openvpn.server
   # Should show: openvpn.server.enabled='1'
   ```

5. **Manual restart to verify configuration:**
   ```bash
   /etc/init.d/openvpn restart
   # Should start without errors
   ```

### Need to Regenerate Client Config

**Menu Option: 11**

```
11) Generate single .ovpn config file
Enter client name: laptop
```

## Advanced Usage

### Multiple Server Instances

Create separate VPN servers for different purposes:

```
# Create "office_vpn" instance
Menu: i → n → office_vpn

# Configure on different port
Menu: 1 → Edit OVPN_PORT before generating

# Generate config for new instance
Menu: 1
```

### Custom Configuration

Edit variables at the top of the script before running:

```bash
OVPN_PORT="1194"              # VPN port
OVPN_PROTO="udp"              # Protocol: udp or tcp
OVPN_POOL="10.8.0.0 255.255.255.0"  # IPv4 VPN subnet
OVPN_IPV6_POOL="fd42:4242:4242:1194::/64"  # IPv6 VPN subnet
OVPN_IPV6_POOL_SIZE="253"     # Max clients
```



# IPv6 VPN Tunnel Setup

This section provides detailed guidance for setting up IPv6 on your OpenVPN server, enabling VPN clients to access IPv6 resources and receive globally routable IPv6 addresses.

## Why Enable IPv6?

- **Future-proofing:** IPv6 is the future of internet addressing
- **Globally routable addresses:** VPN clients can access IPv6-only resources
- **No NAT required:** Direct end-to-end connectivity
- **Dual-stack support:** Clients get both IPv4 (10.8.0.x) and IPv6 addresses

## IPv6 Configuration Options

### Option 1: Globally Routable IPv6 (Recommended)

Use this if your ISP provides IPv6 prefix delegation. VPN clients will receive real, internet-routable IPv6 addresses.

**Prerequisites:**
- Your router has IPv6 connectivity from ISP
- You have a delegated prefix (typically /56 or /64)

**Example: ISP provides /56 delegation**

If your ISP delegates `2001:db8:1234::/56`, you can use any /64 subnet within it:

```bash
# Available subnets from 2001:db8:1234::/56:
# 2001:db8:1234:0::/64    (LAN)
# 2001:db8:1234:1::/64    (Guest network)
# 2001:db8:1234:1194::/64 (OpenVPN) ← Recommended for VPN
# ... up to 2001:db8:1234:ff::/64
```

**Script Configuration:**
```bash
OVPN_IPV6_ENABLE="yes"
OVPN_IPV6_MODE="static"
OVPN_IPV6_POOL="2001:db8:1234:1194::/64"  # Dedicated /64 for VPN
OVPN_IPV6_POOL_SIZE="100"                  # Limit to 100 clients
```

**How to configure in the script:**
1. Run **Option 0** - Auto-detect will show your ISP's IPv6 delegation
2. Run **Option 3** - Enable IPv6
3. Select **Mode 1** (Static pool - recommended)
4. Enter your chosen /64 subnet: `2001:db8:1234:1194::/64`
5. Set max clients (default 253, or lower like 100)

### Option 2: Private IPv6 (ULA)

Use this if:
- Your ISP doesn't provide IPv6
- You only need IPv6 connectivity between VPN clients and LAN
- You want private, non-routable IPv6 addresses

**Generate ULA Prefix:**
1. Visit: https://unique-local-ipv6.com/
2. Generate a random ULA prefix (e.g., `fd42:4242:4242::/48`)
3. Use a /64 subnet from it for VPN (e.g., `fd42:4242:4242:1194::/64`)

**Script Configuration:**
```bash
OVPN_IPV6_ENABLE="yes"
OVPN_IPV6_MODE="static"
OVPN_IPV6_POOL="fd42:4242:4242:1194::/64"  # Private ULA
OVPN_IPV6_POOL_SIZE="253"
```

**Limitation:** VPN clients can only access IPv6 resources on your LAN, not the internet.

## What Gets Configured

When you enable IPv6 and generate the server configuration (Option 1), the script creates `/etc/openvpn/server.conf` with these IPv6 directives:

```conf
# IPv6 configuration
server-ipv6 2001:db8:1234:1194::/64
tun-ipv6
ifconfig-ipv6 2001:db8:1234:1194::1 2001:db8:1234:1194::2

# IPv6 push routes and DNS
push "tun-ipv6"
push "route-ipv6 2000::/3"
push "dhcp-option DNS6 2001:db8:1234:1194::1"
```

**What each directive does:**
- `server-ipv6` - Assigns the IPv6 subnet to VPN clients
- `tun-ipv6` - Enables IPv6 on the tunnel interface
- `ifconfig-ipv6` - Sets server (::1) and client (::2) tunnel endpoints
- `push "tun-ipv6"` - Tells clients to enable IPv6
- `push "route-ipv6 2000::/3"` - Routes all global IPv6 traffic through VPN
- `push "dhcp-option DNS6"` - Provides IPv6 DNS server to clients

## Firewall Configuration

The script automatically configures IPv6 firewall rules when you run **Option 15** (Configure VPN firewall access):

```bash
# Enables IPv6 forwarding
net.ipv6.conf.all.forwarding=1

# Adds VPN interface to LAN zone (allows IPv6 routing)
uci add_list firewall.lan.device="tun+"

# Opens OpenVPN port for both IPv4 and IPv6
uci set firewall.ovpn.family="any"
```

## Verifying IPv6 Configuration

### On the OpenVPN Server

**1. Check IPv6 forwarding is enabled:**
```bash
cat /proc/sys/net/ipv6/conf/all/forwarding
# Should output: 1
```

**2. Check tunnel interface has IPv6:**
```bash
ip -6 addr show tun0
# Should show: inet6 2001:db8:1234:1194::1/64
```

**3. Monitor IPv6 usage:**
- Run **Option 16** in the script
- Select the server instance
- View IPv6 addresses and connected clients

### On VPN Client (After Connecting)

**1. Check client received IPv6 address:**
```bash
# Linux/Mac:
ifconfig tun0 | grep inet6

# Windows:
ipconfig | findstr "IPv6"

# Should show something like: 2001:db8:1234:1194::1002
```

**2. Test IPv6 connectivity:**
```bash
# Ping Google's IPv6 DNS
ping6 2001:4860:4860::8888

# Ping by hostname
ping6 google.com
```

**3. Verify traffic routes through VPN:**
```bash
# Check your public IPv6 address
curl -6 ifconfig.co

# Should return an IPv6 address from your VPN subnet
# Example: 2001:db8:1234:1194::1002
```

**4. Test IPv6 website access:**
```bash
curl -6 https://ipv6.google.com
# Should load successfully
```

## Common IPv6 Issues and Solutions

### Issue: Clients don't get IPv6 addresses

**Solution:**
1. Verify IPv6 is enabled in server.conf:
   ```bash
   grep "server-ipv6" /etc/openvpn/server.conf
   ```
2. Check server logs:
   ```bash
   logread | grep openvpn
   ```
3. Ensure client supports IPv6 (OpenVPN 2.4+)

### Issue: IPv6 connectivity doesn't work

**Checklist:**
- [ ] IPv6 forwarding enabled: `cat /proc/sys/net/ipv6/conf/all/forwarding` = 1
- [ ] Firewall allows IPv6: Run **Option 14** to verify
- [ ] ISP provides IPv6: Test with `ping6 google.com` from router
- [ ] Correct subnet configured: Must be from your ISP's delegation

**Debug commands:**
```bash
# Check routes on server
ip -6 route show dev tun0

# Check neighbor discovery
ip -6 neigh show dev tun0

# View firewall rules
ip6tables -L -v -n
```

### Issue: Only some IPv6 sites work

**Cause:** MTU/fragmentation issues with IPv6

**Solution:**
Add to server.conf:
```conf
mssfix 1420
tun-mtu 1500
```

Then restart: `/etc/init.d/openvpn restart server`

## IPv6 Address Pool Management

Monitor and limit IPv6 address usage:

**Check current usage:**
- Run **Option 16** (Monitor VPN address usage)
- Shows: active IPv6 addresses, connected clients, remaining capacity

**Adjust pool size:**
- Run **Option 3** (Toggle IPv6 support)
- Select **Option 3** (Change max clients limit)
- Enter new limit (e.g., 50, 100, 253)

**View all allocated addresses:**
```bash
ip -6 neigh show dev tun0
```

## Advanced: DHCPv6 Mode (Not Recommended for Most Users)

### What is DHCPv6 Mode?

DHCPv6 mode uses OpenWrt's `odhcpd` service to provide stateful IPv6 address assignment with lease tracking. This is more complex than static mode but offers:
- Detailed lease tracking and logging
- Dynamic address assignment
- Integration with OpenWrt's DHCP infrastructure

**Important:** The script does NOT automatically configure DHCPv6. It validates prerequisites and provides a configuration guide, but you must configure `odhcpd` manually.

### Built-in Prerequisite Checker

When you select DHCPv6 mode (Option 3), the script automatically:

1. **Checks if odhcpd is installed**
   ```
   Checking for odhcpd package...
     ✓ odhcpd is installed
   ```
   Or shows installation command if missing

2. **Checks if odhcpd is running**
   ```
   Checking if odhcpd is running...
     ✓ odhcpd service is running
   ```
   Or shows start/enable commands if not running

3. **Displays manual configuration guide**
   - UCI configuration examples
   - Network interface setup
   - Service restart commands

### How to Enable DHCPv6 Mode

**Step 1: Run the prerequisite check**
```bash
# In the script menu:
3) Toggle IPv6 support
Enable IPv6 support? (yes/no): yes

Select IPv6 mode:
  1) Static pool (recommended)
  2) DHCPv6-PD (advanced)

Select mode (1-2): 2

WARNING: DHCPv6 mode is ADVANCED and requires manual configuration
Check prerequisites and show configuration guide? (y/n): y
```

**Step 2: Review the prerequisite check results**

The script will check:
- Is odhcpd installed? If not: `opkg update && opkg install odhcpd`
- Is odhcpd running? If not: `/etc/init.d/odhcpd start && /etc/init.d/odhcpd enable`

**Step 3: Follow the manual configuration guide**

The script displays the complete configuration. Here's what you need to do:

**3a. Configure odhcpd for VPN interface**

Edit `/etc/config/dhcp` and add:
```bash
config dhcp 'vpn'
    option interface 'vpn'
    option ra 'server'
    option dhcpv6 'server'
    option ra_management '1'
```

**3b. Configure network interface**

Edit `/etc/config/network` and add:
```bash
config interface 'vpn'
    option proto 'none'
    option ifname 'tun0'
```

**3c. Apply the configuration**
```bash
uci commit dhcp
uci commit network
/etc/init.d/network reload
/etc/init.d/odhcpd restart
```

**Step 4: Generate OpenVPN configuration**

Run Option 1 (Generate/Update server.conf). The script will:
- Warn that it's generating static configuration
- Ask for confirmation to continue
- Generate standard static IPv6 configuration (same as static mode)

**Important:** The OpenVPN configuration itself is still static. The DHCPv6 mode setting tells the script you're managing IPv6 addressing via odhcpd externally.

### What Actually Happens

**Script-generated configuration:**
```conf
# IPv6 configuration (same as static mode)
server-ipv6 2001:db8:1234:1194::/64
tun-ipv6
ifconfig-ipv6 2001:db8:1234:1194::1 2001:db8:1194::2
```

**Your manual odhcpd configuration:**
- Handles lease assignment
- Tracks connected clients
- Logs address allocations

### Monitoring DHCPv6 Leases

**View active leases:**
```bash
cat /tmp/hosts/odhcpd
```

**Monitor odhcpd logs:**
```bash
logread | grep odhcpd
```

**Use the script's monitoring (Option 16):**
- Shows connected clients
- Displays IPv6 addresses in use
- Works with both static and DHCPv6 modes

### When to Use DHCPv6 Mode

**Use DHCPv6 if you:**
- Need detailed lease tracking and logging
- Want integration with existing odhcpd infrastructure
- Have specific compliance requirements for address tracking
- Are comfortable with manual UCI configuration

**Use Static mode (recommended) if you:**
- Want simple, automated setup
- Don't need detailed lease tracking
- Want the script to handle everything
- Are setting up OpenVPN for the first time

### Verification

After manual configuration, verify odhcpd is working:

**Check odhcpd is serving the VPN interface:**
```bash
uci show dhcp.vpn
# Should show your configuration
```

**Check interface exists:**
```bash
ifconfig tun0
# Should show the tunnel interface
```

**Test RA (Router Advertisement):**
```bash
# From a connected VPN client:
ip -6 addr show tun0
# Should show an IPv6 address from your pool
```

**Check odhcpd logs:**
```bash
logread | grep "odhcpd.*vpn"
# Should show DHCPv6 activity
```

### Troubleshooting DHCPv6

**odhcpd not assigning addresses:**
1. Verify odhcpd is running: `ps | grep odhcpd`
2. Check configuration: `uci show dhcp.vpn`
3. Restart: `/etc/init.d/odhcpd restart`
4. View logs: `logread -f | grep odhcpd`

**Clients not receiving RA:**
1. Check `ra` is set to `server` in UCI
2. Verify `ra_management` is `1`
3. Check IPv6 forwarding: `cat /proc/sys/net/ipv6/conf/all/forwarding`

**Still having issues:**
1. Consider using static mode instead
2. Check OpenWrt forums for odhcpd configuration
3. Verify your OpenWrt version supports odhcpd

### Why Static Mode is Recommended

**Script automation:**
- Static mode is fully automated by the script
- No manual configuration needed
- Works immediately after generation

**Simplicity:**
- Single configuration file (server.conf)
- No additional services to manage
- Fewer moving parts to troubleshoot

**Reliability:**
- OpenVPN handles all address assignment
- No dependency on external DHCP service
- Works even if odhcpd fails

**For 99% of users, static mode provides everything needed without the complexity.**