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

# interfaces to listen on for srm requests
interfaces=eth0

# node of this server
node=0

# list of volumes available to all clients
volumes=SYSTEMS;SRM

# accept clients who didn't send a SRM_CONNECT request?
accept_unknown=1

# list of clients in <ethernet address>=<ip address>
# the ip address will be sent to the client in the SRM
# connect response.
08:00:09:06:a1:f1=172.16.1.2

# volume configuration
[SYSTEMS]
# volume index
volume=10

# path on filesystem below chroot path above
path=/SYSTEMS

# permissions
umask=027

[SRM]
volume=8
path=/SRM
uid=srm
gid=srmusers

[USER]
volume=9
path=/user

# SRM client configuration
[172.16.1.2]
# list of volumes available in addition to global list
volumes=USER

# SRM node ID of the client
hostnode=0
node=1

# volume where boot files reside
bootpath=SRM:/SYSTEMS

# visible bootfiles 
bootfiles=SYSTEM_P;SYSTEM_B64

# map temp directory to /tmp
tempdir = /tmp
```
