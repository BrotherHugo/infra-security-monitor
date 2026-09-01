# Infra Security Monitor (ismd)

BINARY   := ismd
MAIN     := ./cmd/ismd
BIN_DIR  := bin
OUT      := $(BIN_DIR)/$(BINARY)

CONFIG   ?= /etc/ism/config.yaml
DB       ?= /var/lib/ism/ism.db

GOOS     ?= $(shell go env GOOS)
GOARCH   ?= $(shell go env GOARCH)

# Manual host install (make install): /usr/local/bin, /etc/systemd/system
PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
DOCDIR   ?= $(PREFIX)/share/doc/ismd

.PHONY: help build test clean run once install uninstall deb build-linux build-linux-arm64

help: ## List targets
	@grep -E '^[a-zA-Z0-9_.-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

build: ## Build bin/ismd
	@mkdir -p $(BIN_DIR)
	go build -o $(OUT) $(MAIN)

build-linux: ## Cross-build linux/amd64 -> bin/ismd-linux-amd64
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/$(BINARY)-linux-amd64 $(MAIN)

build-linux-arm64: ## Cross-build linux/arm64 -> bin/ismd-linux-arm64
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/$(BINARY)-linux-arm64 $(MAIN)

test: ## go test ./...
	go test ./...

clean: ## Remove bin/ and dist/
	rm -rf $(BIN_DIR) dist/

install: build ## Install on host (sudo): binary, unit, dirs, config if missing
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(OUT) $(DESTDIR)$(BINDIR)/$(BINARY)
	install -d $(DESTDIR)/etc/ism
	install -d $(DESTDIR)/var/lib/ism/reports
	@if [ ! -f $(DESTDIR)/etc/ism/config.yaml ]; then \
		install -m 0644 configs/config.example.yaml $(DESTDIR)/etc/ism/config.yaml; \
		chmod 0600 $(DESTDIR)/etc/ism/config.yaml; \
	fi
	install -d $(DESTDIR)$(DOCDIR)
	install -m 0644 README.md $(DESTDIR)$(DOCDIR)/README.md
	install -d $(DESTDIR)/etc/systemd/system
	install -m 0644 deploy/systemd/ismd.service $(DESTDIR)/etc/systemd/system/$(BINARY).service

uninstall: ## Remove make install files (leaves /etc/ism and /var/lib/ism)
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY)
	rm -f $(DESTDIR)/etc/systemd/system/$(BINARY).service
	rm -rf $(DESTDIR)$(DOCDIR)
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1; then \
		systemctl disable --now $(BINARY).service 2>/dev/null || true; \
		systemctl daemon-reload 2>/dev/null || true; \
	fi

deb: ## Build .deb via goreleaser (snapshot -> dist/)
	goreleaser release --snapshot --clean --skip=archive

run: build ## Run daemon (schedule from config)
	$(OUT) --config $(CONFIG) --db $(DB)

once: build ## One report cycle and exit
	$(OUT) --config $(CONFIG) --db $(DB) --once
