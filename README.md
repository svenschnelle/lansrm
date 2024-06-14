## What's this?

This repository implements a SRM server running on Linux. SRM (Shared Resource Manager)
was a custom Network type used with HP9000 machines. It used either custom SDLC type
communication. HP98629A was serial RS-422, HP50962A coaxial cabling. Later SRM-UX
was introduced, which used standard UDP/IP over Ethernet.

## Building lansrm

lansrm uses glib-2, so you need the glib2 devel package installed. There's no
configure script - just a make should be enough to build lansrm. make install
will install lansrm to /usr/sbin. Copy srm.ini from the repository to /etc/srm.ini.

## configuring lansrm

A sample /etc/srm.ini looks like this:
```ini
[global]
# mask of debug messages to enable
debug=1

# chroot to this path during server startup (all volume
# paths are below this path)
chroot=/srm

# interface to listen on for srm requests
interface=eth0

# node of this server
node=0

# IP address of this server
hostip=172.16.1.1

# list of volumes available to all clients
volumes=SYSTEMS;BOOT

# accept clients who didn't send a SRM_CONNECT request?
accept_unknown=1

# list of clients in <ethernet address>=<ip address>
# the ip address will be sent to the client in the SRM
# connect response.
08:00:09:06:a1:f1=172.16.1.2

# volume configuration
[SYSTEMS]
# volume index
volume=0

# path on filesystem below chroot path above
path=/SYSTEMS

[BOOT]
volume=8
path=/BOOT

[HP340]
volume=1
path=/HP340

# SRM client configuration
[172.16.1.2]
# list of volumes available in addition to global list
volumes=HP340
# SRM node ID of the client
node=1
```
