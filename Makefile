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
	@echo "  make version-bump V=x.y.z  同步改四处版本号（漏一处就有测试挂）"
	@echo "  make web        构建前端并输出到 internal/web/dist"
	@echo "  make build      构建当前平台二进制到 $(DIST)/"
	@echo "  make release    交叉编译 linux/amd64 与 linux/arm64"
	@echo "  make test       运行单元测试、go vet 与编译检查"
	@echo "  make smoke      对已启动的实例跑接口冒烟测试"
	@echo "  make clean      清理构建产物"
	@echo
	@echo "发版流程：make version-bump V=0.0.1-pre.07 → 提交 → 推 main"
	@echo "          → 等 main 的 CI 跑绿 → 再打同名 tag 推送"
	@echo "          CI 会校验 tag 与 VERSION 一致后自动构建并创建 Release"
	@echo
	@echo "          第 2 步不能省：internal/version 里有一条测试要求默认版本号"
	@echo "          与 VERSION 文件一致。漏改的话 CI 直接红，此时若已经把 tag"
	@echo "          推上去，Release 会在同一步失败 —— 而失败前不会产出任何资产。"

.PHONY: version
version:
	@echo "$(VERSION)"

# ---------- 版本号 ----------

# 版本号散落在四处，只改 VERSION 会让 TestDefaultVersionMatchesVersionFile
# 挂掉。逻辑放在 scripts/version-bump.sh 里而不是写在这里 —— 开发机上不一定
# 有 make，脚本可以直接跑、也能被测试覆盖。
.PHONY: version-bump
version-bump:
	@test -n "$(V)" || { echo "用法：make version-bump V=0.0.1-pre.07" >&2; exit 1; }
	bash scripts/version-bump.sh "$(V)"

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
