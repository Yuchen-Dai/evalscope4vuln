"""图灵平台 HTTP client（唯一对接缝）。

封装 fake_turing 的 REST 接口：创建项目 / 平台与探测类型 / 提交扫描(Form) /
查状态 / 取结果(overview+data)。并提供 finding 原始 dict → 规范化 Finding 的解析。

真实图灵平台契约确认后，只改本文件，上层评测逻辑不动。
关键契约（见 fake_turing/docs/api-reference.md）：
- 无鉴权；POST /scan 是 Form body（非 JSON）。
- report-overview 已剥离 call_chain 等大字段（仅留 source/sink）；report-data 为完整版。
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

from evalscope.benchmarks.vuln_scan import config
from evalscope.benchmarks.vuln_scan.schemas import Finding, Loc, ScanConfig
from evalscope.benchmarks.vuln_scan.scoring.type_map import normalize


def _as_json(value: Any) -> Any:
    """图灵部分字段是 JSON 字符串，需要反序列化；已解析的直通。"""
    if isinstance(value, str):
        s = value.strip()
        if s and s[0] in "[{":
            try:
                return json.loads(s)
            except (ValueError, TypeError):
                return None
        return None
    return value


def parse_finding(raw: dict) -> Finding:
    """把图灵 finding dict 解析为规范化 Finding（提取 source/sink/call_chain 位置）。"""
    locations: list[Loc] = []

    for key in ("source", "sink"):
        obj = _as_json(raw.get(key))
        if isinstance(obj, dict) and (obj.get("file") or obj.get("line")):
            locations.append(Loc(file=obj.get("file"), line=obj.get("line")))

    cc = _as_json(raw.get("call_chain"))
    if isinstance(cc, dict):
        cc = [cc]
    if isinstance(cc, list):
        for step in cc:
            if isinstance(step, dict) and (step.get("file") or step.get("line")):
                locations.append(Loc(file=step.get("file"), line=step.get("line")))

    # 去重 (file, line)
    seen: set[tuple] = set()
    uniq: list[Loc] = []
    for loc in locations:
        key = (loc.file, loc.line)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(loc)

    vt = raw.get("vuln_type") or ""
    sev = str(raw.get("severity") or "MEDIUM").strip().upper()
    return Finding(
        finding_id=raw.get("id") or raw.get("finding_id") or "",
        display_id=raw.get("display_id"),
        vuln_type=vt,
        vuln_type_norm=normalize(vt),
        severity=sev,
        confidence=int(raw.get("confidence") or 0),
        validation_result=raw.get("validation_result"),
        title=raw.get("title"),
        locations=uniq,
        raw=raw,
    )


def parse_findings(raw_list: list[dict]) -> list[Finding]:
    return [parse_finding(r) for r in raw_list if isinstance(r, dict)]


class TuringClient:
    """异步图灵平台 client。"""

    def __init__(self, base_url: str | None = None, timeout: float | None = None):
        self.base_url = (base_url or config.TURING_BASE_URL).rstrip("/")
        # trust_env=False：不读环境的 HTTP_PROXY/ALL_PROXY（本地对接 fake_turing 时，
        # 环境里的 socks 代理会让 httpx 报 "Unknown scheme for proxy URL socks://"）。
        # 真实图灵平台若需走代理，改这里即可（唯一对接缝）。
        self._client = httpx.AsyncClient(base_url=self.base_url,
                                         timeout=timeout or config.HTTP_TIMEOUT,
                                         trust_env=False,
                                         headers={"X-Requested-With": "XMLHttpRequest"})

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---- 鉴权 ----
    async def login(self, username: str, password: str) -> None:
        """登录图灵平台。

        正式平台校验账密后 set-cookie ``turing_session``，后续所有 API 强制校验；
        httpx AsyncClient 的 cookie jar 会自动保存并在后续请求带上（同一实例）。
        fake_turing 的 ``/api/auth/login`` 永远成功且不设 Cookie、不校验，故无条件调用安全。
        """
        r = await self._client.post('/api/auth/login', json={'username': username, 'password': password})
        r.raise_for_status()

    # ---- 元/健康 ----
    async def health(self) -> dict:
        r = await self._client.get("/health")
        r.raise_for_status()
        return r.json()

    # ---- 项目 ----
    async def upload_project(self, display_name: str, filename: str, source_path: str,
                             version: str = "1.0.0") -> str:
        """上传源码压缩包创建项目（POST /api/projects/upload，multipart）。

        真实图灵是 server-side 扫描：代码经上传交给图灵，不依赖图灵服务器本地路径
        （/projects/local 的 local_path 在服务器不存在会 400）。
        multipart：文件字段 name=file、filename=<源码文件名>；外加 display_name（项目名，
        重复判断依据）+ version。重复（display_name+version 已存在）返 409。
        display_name 用 project_name（用户每次填的唯一名）→ 不会重复。
        """
        with open(source_path, "rb") as f:
            files = {"file": (filename, f)}
            data = {"display_name": display_name, "version": version}
            r = await self._client.post("/api/projects/upload", files=files, data=data)
        r.raise_for_status()
        return r.json().get("project_id") or config.FALLBACK_PROJECT_ID

    # ---- 配置 ----
    async def list_platforms(self) -> list[dict]:
        r = await self._client.get("/api/platforms")
        r.raise_for_status()
        return r.json()

    async def list_detect_types(self, platform: str) -> list[dict]:
        r = await self._client.get(f"/api/platforms/{platform}/detect-types")
        r.raise_for_status()
        return r.json()

    # ---- 扫描（Form body）----
    async def submit_scan(self, project_id: str, cfg: ScanConfig) -> str:
        form = {
            "platforms": cfg.platforms,
            "detect_types": cfg.detect_types,
            "priority": cfg.priority,
            "model_name": cfg.model_name,
            "max_concurrency": cfg.max_concurrency,
            "phase1_timeout": cfg.phase1_timeout,
            "phase2_timeout": cfg.phase2_timeout,
            "phase3_timeout": cfg.phase3_timeout,
        }
        r = await self._client.post(f"/api/projects/{project_id}/scan", data=form)
        # 真实图灵可能返 303 重定向，location: /scan/{pid}/status/{job_id}，job_id 在 url 末段
        if r.status_code in (301, 302, 303, 307, 308):
            return r.headers.get("location", "").rstrip("/").split("/")[-1] or ""
        r.raise_for_status()
        return r.json().get("job_id") or ""

    # ---- 状态与结果 ----
    async def get_status(self, project_id: str, job_id: str) -> dict:
        r = await self._client.get(f"/api/projects/{project_id}/status/{job_id}")
        r.raise_for_status()
        return r.json()

    async def get_report_overview(self, project_id: str, job_id: str) -> dict:
        r = await self._client.get(f"/api/projects/{project_id}/report-overview",
                                   params={"job_id": job_id})
        r.raise_for_status()
        return r.json()

    async def get_report_data(self, project_id: str, job_id: str) -> dict:
        r = await self._client.get(f"/api/projects/{project_id}/report-data",
                                   params={"job_id": job_id})
        r.raise_for_status()
        return r.json()
