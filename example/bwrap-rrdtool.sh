#! /bin/sh

# This example uses bubblewrap to put rrdtool into a 
# bubblewrap sandbox such that it can only access files
# in a read only way.
#
# The rrd files are in /var/lib/collectd.
#
# To run this example run ./rrdsrv -config ./example/jail.cfg


set -euo pipefail

rrdtool=$(which rrdtool)

# tweak for your linux distro
if uname -a | grep -q "NixOS"
then
  binds="
      --ro-bind /bin /bin
      --ro-bind /usr /usr
      --ro-bind /run /run
      --ro-bind /nix /nix
  "
else
  binds="
     --ro-bind /bin /bin
     --ro-bind /sbin /sbin
     --ro-bind /usr /usr
     --ro-bind /lib /lib
     --ro-bind /run/ /run
  "
fi

exec bwrap \
      $binds \
      --dir /etc \
      --dir /tmp \
      --dir /var \
      --dir /var/lib \
      --ro-bind /var/lib/collectd /var/lib/collectd \
      --symlink ../tmp var/tmp \
      --proc /proc \
      --dev /dev \
      --chdir /var/lib/collectd \
      --unshare-all \
      --die-with-parent \
      $rrdtool "$@"