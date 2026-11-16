
#!/bin/sh
set -eu

# Start the system D-Bus service.
mkdir -p /run/dbus
dbus-daemon --system --fork

# Start Avahi, which provides DNS-SD support.
avahi-daemon --daemonize --no-chroot

# Start the software IPP printer.
exec ippeveprinter \
  -r off \
  -p 8631 \
  -v \
  DAT505-Lab-Printer

