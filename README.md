# Corprox

A cli utility to run a corporate vpn while preserving normal routing. Modifies the OpenVpn config to
only route specfied ip nets via the vpn. Also sets up correct DNS resolution with systemd-resolved.

## TODO

- [ ] Maybe include reverse dns lookup into resolved dbus call. 


