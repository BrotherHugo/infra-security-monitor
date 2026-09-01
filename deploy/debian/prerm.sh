#!/bin/sh
set -e

case "$1" in
remove|upgrade|deconfigure)
	if command -v deb-systemd-helper >/dev/null 2>&1; then
		deb-systemd-helper disable ismd.service 2>/dev/null || true
		deb-systemd-helper mask ismd.service 2>/dev/null || true
	elif command -v systemctl >/dev/null 2>&1; then
		systemctl stop ismd.service 2>/dev/null || true
		systemctl disable ismd.service 2>/dev/null || true
	fi
	;;
esac

exit 0
