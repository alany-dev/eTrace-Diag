#!/usr/bin/env python3
"""eTrace-Diag viz 静态服务。

同时提供 tools/viz 前端页面与项目根会话输出目录（默认 <项目根>/out）：
  GET /...            -> tools/viz/  （前端页面 / js / vendor）
  GET /out/...        -> <项目根>/out/...  （会话目录列表 + etrace.sqlite3）

页面打开后即可列出并选择 out/ 下的会话，无需任何额外配置（不依赖
python -m http.server --directory，也不受其服务根限制）。

用法：
  python3 tools/viz/serve.py [--port 8901] [--out <会话输出目录>]
环境变量：ETRACE_VIZ_PORT / ETRACE_VIZ_OUT
"""
import argparse
import os
import posixpath
import sys
import urllib.parse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# serve.py 位于 <项目根>/tools/viz/ → 上溯三级到项目根
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VIZ = os.path.join(ROOT, "tools", "viz")


class Handler(SimpleHTTPRequestHandler):
    """两段式路径映射：/out/... -> 会话输出目录；其余 -> tools/viz。"""

    def __init__(self, *args, out_dir=None, **kwargs):
        self.out_dir = out_dir or os.path.join(ROOT, "out")
        super().__init__(*args, **kwargs)

    def translate_path(self, path):
        path = path.split("?", 1)[0].split("#", 1)[0]
        path = posixpath.normpath(urllib.parse.unquote(path))
        words = [w for w in path.split("/") if w]
        # 兜底别名：/tools/viz/out/... 与 /out/... 等价
        if words[:2] == ["tools", "viz"] and len(words) > 2 and words[2] == "out":
            words = ["out"] + words[3:]
        if words and words[0] == "out":
            base = self.out_dir
            words = words[1:]
        else:
            # 兼容两种页面路径：/tools/viz/...（推荐）与根路径 /...
            if words[:2] == ["tools", "viz"]:
                words = words[2:]
            base = VIZ
        # 与 SimpleHTTPRequestHandler 相同的安全解析（过滤 . / .. 逃逸）
        result = base
        for word in words:
            _drive, word = os.path.splitdrive(word)
            _head, word = os.path.split(word)
            if word in (os.curdir, os.pardir):
                continue
            result = os.path.join(result, word)
        return result


def main():
    ap = argparse.ArgumentParser(description="eTrace-Diag viz 静态服务（前端 + 会话输出目录）")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("ETRACE_VIZ_PORT", "8901")))
    ap.add_argument("--out", default=os.environ.get("ETRACE_VIZ_OUT", os.path.join(ROOT, "out")),
                    help="会话输出根目录（默认 <项目根>/out）")
    args = ap.parse_args()

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", args.port),
                                 partial(Handler, out_dir=out_dir))
    print(f"eTrace-Diag viz: http://127.0.0.1:{args.port}/tools/viz/index.html")
    print(f"  会话输出目录: {out_dir}   （页面 /out/ 映射至此）")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
