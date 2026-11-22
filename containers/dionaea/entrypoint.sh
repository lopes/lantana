#!/bin/sh
# Non-destructive unprivileged entrypoint for ghcr.io/lopes/lantana-dionaea.
# Runs directly as dionaea (UID 1000 / GID 1000) with zero Linux capabilities:
# refuses symlinks on bind-mounted roots/subdirs/logfiles, ensures required
# runtime subdirectories exist without `cp -a` (preserving host POSIX ACLs),
# and execs dionaea directly without privilege-drop syscalls.
set -eu

DATA_ROOT=/opt/dionaea/var/lib/dionaea
LOG_ROOT=/opt/dionaea/var/log/dionaea

if [ -L "$DATA_ROOT" ] || [ -L "$LOG_ROOT" ]; then
    echo "Refusing symlink on state/log root" >&2
    exit 1
fi

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

for logfile in \
    "$LOG_ROOT/dionaea.log" \
    "$LOG_ROOT/dionaea-errors.log" \
    "$LOG_ROOT/dionaea.json"
do
    if [ -L "$logfile" ]; then
        echo "Refusing symlink on log file: $logfile" >&2
        exit 1
    fi
done

exec /opt/dionaea/bin/dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg "$@"
