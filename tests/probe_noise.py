"""LinkFinder 结果噪音测试：评估提取结果是否混入非 API 路径。"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
from core.prefilter import prefilter_js

# 模拟一段真实前端 JS：API 路径 + CDN/图片/字体等噪音混在一起
JS = """
var API = { login: "/api/v1/auth/login", list: "/api/v2/items" };
var cdn = "https://cdn.example.com/lib/vue.min.js";
var img = "https://img.example.com/banner/hero.png";
var font = "https://fonts.example.com/assets/icon.woff2";
var css = "/static/css/main.a1b2.css";
var dataUri = "data:image/png;base64,iVBORw0KGgo=";
var track = "https://hm.baidu.com/hm.js?abcdef";
"""

pf = prefilter_js(JS, 40, 4000)
print("api_paths 提取结果：")
for p in pf.api_paths:
    print(f"  - {p}")
print(f"\n共 {len(pf.api_paths)} 条")
