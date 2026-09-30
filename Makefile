SHELL := /bin/bash

MODULE   := github.com/dreamstation625/FrpFireWall

# 版本号的唯一来源是 VERSION 文件；CI 里可用环境变量覆盖。
# 文件缺失或为空时回落到 0.0.0，避免把空串注入进去导致版本号解析失败。
VERSION  ?= $(shell v=$$(cat VERSION 2>/dev/null | tr -d ' \t\r\n'); echo $${v:-0.0.0})
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
	@echo "  make version    显示将要编译进二进制的版本号"
	@echo "  make web        构建前端并输出到 internal/web/dist"
	@echo "  make build      构建当前平台二进制到 $(DIST)/"
	@echo "  make release    交叉编译 linux/amd64 与 linux/arm64"
	@echo "  make test       运行单元测试、go vet 与编译检查"
	@echo "  make smoke      对已启动的实例跑接口冒烟测试"
	@echo "  make clean      清理构建产物"
	@echo
	@echo "发版流程：改 VERSION → 提交 → 打同名 tag 推送（如 v0.0.1-pre.01）"
	@echo "          CI 会校验 tag 与 VERSION 一致后自动构建并创建 Release"

.PHONY: version
version:
	@echo "$(VERSION)"

# ---------- 前端 ----------

.PHONY: web
web:
	cd web && npm install --no-audit --no-fund && npm run build
	@# vite 的 emptyOutDir 会把 .gitkeep 一并删掉，这里补回来，
	@# 否则每次构建都会在 git status 里留下一个「已删除」的条目。
	@test -f internal/web/dist/.gitkeep || git checkout -- internal/web/dist/.gitkeep 2>/dev/null || touch internal/web/dist/.gitkeep
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
	go test ./... -count=1
	go vet ./...
	go build ./...
	@echo "单元测试 / go vet / build 通过"

.PHONY: smoke
smoke:
	bash testdata/smoke.sh

.PHONY: clean
clean:
	rm -rf $(DIST)
	@# 只清内部文件，保留 .gitkeep：go:embed 在 dist 目录不存在时直接编译失败，
	@# 目录被整个删掉会让新克隆的仓库 build 不过。
	@mkdir -p internal/web/dist
	@find internal/web/dist -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec rm -rf {} + 2>/dev/null || true
	@echo "已清理 $(DIST)/ 与 internal/web/dist（保留 .gitkeep）"
