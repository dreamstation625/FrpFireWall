#!/usr/bin/env python3
"""本地假的 GitHub Releases 服务，供 install.sh 的端到端测试使用。

只实现被测脚本真正用到的三个路由：

    HEAD /releases/latest/download/<file>    有正式版时 302 到最新正式版，否则 404
    GET  /releases/download/<tag>/<file>     返回 <root>/<tag>/<file>
    GET  /repos/<owner>/<repo>/releases      <root>/releases.json 的内容（--pre 路径用）

目录布局由测试脚本准备：

    <root>/
      latest           一行文本，内容是最新正式版的 tag（没有正式版时不写此文件）
      releases.json    Releases API 的应答
      v0.0.1/
        frpfirewall-linux-amd64
        frpfirewall.service
        frpfirewall-panic.sh
        sha256sums.txt

刻意不复刻 GitHub 的版本号排序规则 —— 哪个是 latest 由测试直接写在 <root>/latest 里，
假服务只负责照做。这样测试失败时不会被「假服务自己也算错了」干扰。
"""

import argparse
import json
import mimetypes
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = ""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # 打日志，方便测试失败时对照
    def log_message(self, fmt, *args):
        sys.stderr.write("  [fake-gh] %s %s\n" % (self.command, self.path))

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _not_found(self, why):
        self._send(404, json.dumps({"message": why}).encode(), {"Content-Type": "application/json"})

    def _handle(self):
        path = self.path.split("?", 1)[0]

        # ---- 最新正式版的下载跳转 ----
        if path.startswith("/releases/latest/download/"):
            name = path[len("/releases/latest/download/"):]
            latest_file = os.path.join(ROOT, "latest")
            if not os.path.isfile(latest_file):
                # 只有预发布版时 GitHub 就是这个行为
                return self._not_found("Not Found")
            with open(latest_file, encoding="utf-8") as fh:
                tag = fh.read().strip()
            if not tag:
                return self._not_found("Not Found")
            target = "/releases/download/%s/%s" % (tag, name)
            return self._send(302, b"", {"Location": target})

        # ---- 指定 tag 的下载 ----
        if path.startswith("/releases/download/"):
            rest = path[len("/releases/download/"):]
            parts = rest.split("/", 1)
            if len(parts) != 2:
                return self._not_found("bad path")
            tag, name = parts
            # 防目录穿越：文件名与 tag 都不许出现 ..
            for piece in (tag, name):
                if ".." in piece or piece.startswith("/"):
                    return self._not_found("bad path")
            full = os.path.join(ROOT, tag, name)
            if not os.path.isfile(full):
                return self._not_found("Not Found")
            with open(full, "rb") as fh:
                body = fh.read()
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            return self._send(200, body, {"Content-Type": ctype})

        # ---- Releases API ----
        if path.startswith("/repos/") and path.endswith("/releases"):
            api_file = os.path.join(ROOT, "releases.json")
            if not os.path.isfile(api_file):
                return self._send(200, b"[]", {"Content-Type": "application/json"})
            with open(api_file, "rb") as fh:
                return self._send(200, fh.read(), {"Content-Type": "application/json"})

        return self._not_found("Not Found")

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        self._handle()


def main():
    global ROOT
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="发布内容所在目录")
    ap.add_argument("--port", type=int, default=0, help="0 表示让系统分配")
    args = ap.parse_args()

    ROOT = os.path.abspath(args.root)
    if not os.path.isdir(ROOT):
        sys.exit("fake-release-server: 目录不存在 %s" % ROOT)

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    # 把真正监听的端口打到 stdout，测试脚本读这一行
    print(srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
