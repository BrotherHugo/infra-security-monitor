#!/bin/sh
set -e

case "$1" in
configure)
	install -d -m 0750 /etc/ism
	install -d -m 0750 /var/lib/ism/reports
	if [ ! -f /etc/ism/config.yaml ]; then
		install -m 0640 /usr/share/ismd/config.example.yaml /etc/ism/config.yaml
		chmod 0600 /etc/ism/config.yaml
	fi

	if command -v deb-systemd-helper >/dev/null 2>&1; then
		deb-systemd-helper unmask ismd.service 2>/dev/null || true
		deb-systemd-helper enable ismd.service
	elif command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload
		systemctl enable ismd.service
	fi
	;;
esac

exit 0
