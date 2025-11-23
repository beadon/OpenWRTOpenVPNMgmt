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
