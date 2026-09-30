// Package version 保存构建期注入的版本信息。
package version

// 这些变量在构建时通过 -ldflags -X 注入。
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// String 返回可读的版本串。
func String() string {
	if Commit == "unknown" || Commit == "" {
		return Version
	}
	return Version + " (" + Commit + ")"
}
