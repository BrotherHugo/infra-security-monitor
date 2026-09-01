#!/bin/sh
set -e

case "$1" in
purge)
	rm -rf /etc/ism
	if command -v deb-systemd-helper >/dev/null 2>&1; then
		deb-systemd-helper purge ismd.service 2>/dev/null || true
		deb-systemd-helper unmask ismd.service 2>/dev/null || true
	elif command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload 2>/dev/null || true
	fi
	;;
remove|upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
	if command -v deb-systemd-helper >/dev/null 2>&1; then
		deb-systemd-helper update-state ismd.service 2>/dev/null || true
	elif command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload 2>/dev/null || true
	fi
	;;
esac

exit 0
