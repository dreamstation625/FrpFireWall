// Package web 把前端构建产物打进二进制。
//
// 构建流程：先 cd web && npm run build，产物输出到 internal/web/dist，
// 然后 go build 即可得到单文件可执行程序。
package web

import (
	"embed"
	"io/fs"
)

// 注意：dist 目录必须存在（哪怕只有一个占位 index.html），否则编译失败。
//
//go:embed all:dist
var distFS embed.FS

// FS 返回前端静态资源的根文件系统。资源缺失时返回 nil。
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil
	}
	return sub
}
