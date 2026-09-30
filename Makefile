SHELL := /bin/bash

MODULE   := github.com/dreamstation625/FrpFireWall
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILT_AT ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuildTime=$(BUILT_AT)

DIST := dist

.PHONY: help
help:
	@echo "frpfirewall 构建目标"
	@echo "  make web        构建前端并输出到 internal/web/dist"
	@echo "  make build      构建当前平台二进制到 $(DIST)/"
	@echo "  make release    交叉编译 linux/amd64 与 linux/arm64"
	@echo "  make test       运行 go vet 与冒烟测试所需的前置检查"
	@echo "  make smoke      对已启动的实例跑接口冒烟测试"
	@echo "  make clean      清理构建产物"

# ---------- 前端 ----------

.PHONY: web
web:
	cd web && npm install --no-audit --no-fund && npm run build
	@# go:embed 在 dist 不存在时会直接编译失败，这里补一个占位保证可编译
	@test -f internal/web/dist/index.html || echo '<!doctype html><meta charset=utf-8><title>frpfirewall</title><p>前端未构建，请执行 make web' > internal/web/dist/index.html

# ---------- Go ----------

.PHONY: build
build: web
	@mkdir -p $(DIST)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/frpfirewall ./cmd/frpfirewall
	@ls -lh $(DIST)/frpfirewall

.PHONY: release
release: web
	@mkdir -p $(DIST)
	@for target in linux/amd64 linux/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		echo ">>> building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
			-ldflags '$(LDFLAGS)' -o $(DIST)/frpfirewall-$$os-$$arch ./cmd/frpfirewall || exit 1; \
	done
	cd $(DIST) && sha256sum frpfirewall-linux-* > sha256sums.txt && cat sha256sums.txt

.PHONY: test
test:
	go vet ./...
	go build ./...
	@echo "go vet / build 通过"

.PHONY: smoke
smoke:
	bash testdata/smoke.sh

.PHONY: clean
clean:
	rm -rf $(DIST)
	rm -rf internal/web/dist
