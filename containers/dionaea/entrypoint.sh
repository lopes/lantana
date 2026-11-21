#!/bin/sh
# Non-destructive entrypoint for ghcr.io/lopes/lantana-dionaea.
# Ensures required runtime subdirectories exist and are owned by dionaea:dionaea
# without using `cp -a` over host bind-mounts (preserving host POSIX ACLs).
# Because DropCapability=ALL omits CAP_DAC_OVERRIDE, we temporarily own the
# parent state directory as root (via CAP_CHOWN) while creating missing child
# directories, then hand ownership of all writable paths to dionaea:dionaea.
set -eu

DATA_ROOT=/opt/dionaea/var/lib/dionaea
LOG_ROOT=/opt/dionaea/var/log/dionaea

chown 0:0 "$DATA_ROOT"

for subdir in \
    binaries \
    wwwroot \
    tmp \
    ftp/root \
    http/root \
    smb \
    tftp
do
    mkdir -p "$DATA_ROOT/$subdir"
done

for dir in \
    "$LOG_ROOT" \
    "$DATA_ROOT" \
    "$DATA_ROOT/binaries" \
    "$DATA_ROOT/wwwroot" \
    "$DATA_ROOT/tmp" \
    "$DATA_ROOT/ftp" \
    "$DATA_ROOT/ftp/root" \
    "$DATA_ROOT/http" \
    "$DATA_ROOT/http/root" \
    "$DATA_ROOT/smb" \
    "$DATA_ROOT/tftp"
do
    chown dionaea:dionaea "$dir"
done

exec /opt/dionaea/bin/dionaea -u dionaea -g dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg "$@"
