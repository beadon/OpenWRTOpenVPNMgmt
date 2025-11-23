# OpenWRT OpenVPN Management 
Openwrt VPN setup and management script, making management of Open VPN via CLI much simpler.

The All-in-One OpenVPN Management Script
Tired of managing keys, ovpn files and all different parts piecemeal ? Use this script on the CLI to manage it all.


Assuming you have installed wget...
```
opkg update; opkg install wget
```
Then if you are SSSH'd into OpenWRT now, grab then run it like this:
```
wget https://raw.githubusercontent.com/beadon/OpenWRTOpenVPNMgmt/refs/heads/main/openvpn_server_management.sh
chmod 775 openvpn_server_management.sh
./openvpn_server_management.sh
```

# IPV6 Setup
For a router with ISP delegation 2001:db8:1234::/56:

  # You could use any /64 from your delegation, e.g.:
  OVPN_IPV6_POOL="2001:db8:1234:1194::/64"  # Dedicated VPN subnet
  OVPN_IPV6_MODE="static"                    # Simple mode
  OVPN_IPV6_POOL_SIZE="100"                  # Limit to 100 clients

  The generated server.conf will include:
  # IPv6 configuration
  server-ipv6 2001:db8:1234:1194::/64
  tun-ipv6
  ifconfig-ipv6 2001:db8:1234:1194::1 2001:db8:1234:1194::2

  # IPv6 push routes and DNS
  push "tun-ipv6"
  push "route-ipv6 2000::/3"
  push "dhcp-option DNS6 2001:db8:1234:1194::1"



# Test IPv6 connectivity
```
ping6 google.com
```

# Check if you're using IPv6 through the VPN, once connected

```
curl -6 ifconfig.co
```