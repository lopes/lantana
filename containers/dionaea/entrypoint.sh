#!/bin/sh
# Non-destructive entrypoint for ghcr.io/lopes/lantana-dionaea.
# Ensures required runtime subdirectories exist and are owned by dionaea:dionaea
# without using `cp -a` over host bind-mounts (preserving host POSIX ACLs).
# Keeps DATA_ROOT owned by container root (0:0, 0755) so the unprivileged
# dionaea worker (UID 1000) cannot rename or replace top-level subdirs with
# symlinks across restarts, and rejects any symlink before calling `chown -h`.
set -eu

DATA_ROOT=/opt/dionaea/var/lib/dionaea
LOG_ROOT=/opt/dionaea/var/log/dionaea

if [ -L "$DATA_ROOT" ] || [ -L "$LOG_ROOT" ]; then
    echo "Refusing symlink on state/log root" >&2
    exit 1
fi

chown -h 0:0 "$DATA_ROOT"
chmod 0755 "$DATA_ROOT"

for parent in "$DATA_ROOT/ftp" "$DATA_ROOT/http"; do
    if [ -L "$parent" ]; then
        echo "Refusing symlink on parent dir: $parent" >&2
        exit 1
    fi
    if [ -d "$parent" ]; then
        chown -h 0:0 "$parent"
    fi
done

for subdir in \
    binaries \
    wwwroot \
    tmp \
    ftp \
    ftp/root \
    http \
    http/root \
    smb \
    tftp
do
    target="$DATA_ROOT/$subdir"
    if [ -L "$target" ]; then
        echo "Refusing symlink inside state tree: $target" >&2
        exit 1
    fi
    mkdir -p "$target"
    if [ -L "$target" ]; then
        echo "Refusing symlink after mkdir: $target" >&2
        exit 1
    fi
done

for dir in \
    "$LOG_ROOT" \
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
    if [ -L "$dir" ]; then
        echo "Refusing symlink before chown: $dir" >&2
        exit 1
    fi
    chown -h dionaea:dionaea "$dir"
done

exec /opt/dionaea/bin/dionaea -u dionaea -g dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg "$@"
