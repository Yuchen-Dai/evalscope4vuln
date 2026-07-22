"""vulnbench 全局配置。

所有运行期参数集中在此，便于调整与覆盖（环境变量优先）。
端口/主机由 run.sh 通过 uvicorn 参数控制，不在此处。
"""
import os

# ---- 图灵平台（被测端）----
# run.sh 会 export TURING_URL；默认指向本地 fake_turing mock
TURING_BASE_URL = os.environ.get("TURING_URL", "http://127.0.0.1:8088").rstrip("/")

# ---- 轮询 ----
POLL_INTERVAL = float(os.environ.get("VULNBENCH_POLL_INTERVAL", "2.5"))   # 轮询间隔（秒）
POLL_TIMEOUT = float(os.environ.get("VULNBENCH_POLL_TIMEOUT", "1800"))    # 单个 run 总超时（秒）
HTTP_TIMEOUT = float(os.environ.get("VULNBENCH_HTTP_TIMEOUT", "15"))      # 单次 HTTP 请求超时（秒）

# ---- 匹配 ----
LINE_TOLERANCE = int(os.environ.get("VULNBENCH_LINE_TOLERANCE", "5"))     # 行号容差（±N 行）

# ---- 数据 ----
_BASE = os.path.dirname(os.path.abspath(__file__))
GT_DIR = os.environ.get("VULNBENCH_GT_DIR", os.path.join(_BASE, "gt"))
DB_PATH = os.environ.get("VULNBENCH_DB_PATH", os.path.join(_BASE, "vulnbench.db"))
WEB_DIR = os.path.join(_BASE, "web")

# ---- 图灵项目兜底 ----
# fake_turing 的 POST /api/projects/local 永远返回这个固定 project_id
FALLBACK_PROJECT_ID = "e7fc30a7-b63c-439f-8816-7ef22e3ef217"
