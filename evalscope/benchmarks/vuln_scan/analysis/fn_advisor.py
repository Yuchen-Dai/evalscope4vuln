"""FN 漏报路径分析（opencode agent）。

针对图灵漏报的漏洞（GT 有、图灵没报），给 opencode agent 一个 workdir（被测源码
`repo/` + 图灵完整挖掘记录 `sessions.json`），让它自己 read/grep 真实代码与记录、
迭代推理，输出「图灵为何漏挖」的原因与优化建议（帮助图灵自我迭代）。

opencode 经 evalscope 的 run_external_agent + bridge（Responses→ChatCompletions 翻译）
驱动，judge 配置（api_url/model_id/api_key）经 OpenAICompatibleAPI → opencode。

入口：``analyze_one(fn, workdir, jcfg, sample_id)``（async）。
worker（fn_advice_runner）建共享 workdir（解压源码 + dump sessions）后逐个 FN 调用。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from typing import Any

from evalscope.api.dataset import Sample
from evalscope.api.model import GenerateConfig, Model
from evalscope.agent.external import ExternalAgentConfig
from evalscope.agent.external.adapter import run_external_agent
from evalscope.models.openai_compatible import OpenAICompatibleAPI
from evalscope.utils.logger import get_logger

logger = get_logger()

# session 摘要字符上限（防爆 prompt；约 3-4k token）
MAX_SUMMARY_CHARS = 12000


def extract_fn(vuln_match: dict) -> list[dict]:
    """从 vuln_match 提取漏报(FN)的 GT 项（图灵未报出的漏洞）。

    schema:2 取 type 套（类型+位置）的 missed_gt，与前端 FN 标识一致；
    schema:1 取顶层 missed_gt。
    """
    if not vuln_match:
        return []
    if vuln_match.get('schema', 1) >= 2 and vuln_match.get('type'):
        missed = set(vuln_match['type'].get('missed_gt', []))
    else:
        missed = set(vuln_match.get('missed_gt', []))
    gt_list = vuln_match.get('gt', []) or []
    return [g for g in gt_list if g.get('gt_id') in missed]


def relevant_files(fn: dict) -> list[str]:
    """漏洞涉及的关键文件路径：优先 GT 的 source/sink，缺省降级 location.file。

    GT 预埋了 source/sink 时用它（精准定位数据流端点的挖掘记录）；
    老 GT 无 source/sink → 用漏洞位置文件。
    """
    files: list[str] = []
    for key in ('source', 'sink'):
        loc = fn.get(key) or {}
        f = loc.get('file')
        if f:
            files.append(f)
    if not files:
        lf = (fn.get('location') or {}).get('file')
        if lf:
            files.append(lf)
    seen: set[str] = set()
    out: list[str] = []
    for f in files:
        if f and f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _part_text(part: Any) -> str:
    """从 opencode part 提取可读文本（reasoning/text/patch/tool）。"""
    if not isinstance(part, dict):
        return ''
    t = part.get('type')
    if t in ('reasoning', 'text'):
        return part.get('text', '') or ''
    if t == 'patch':
        return 'patch: ' + json.dumps(part.get('patch') or part, ensure_ascii=False)[:400]
    if t == 'tool':
        # opencode tool part：保留工具名 + 入参（可能含读文件路径），去掉 id/time 噪声
        payload = {k: v for k, v in part.items() if k not in ('id', 'sessionID', 'messageID', 'time')}
        return 'tool: ' + json.dumps(payload, ensure_ascii=False)[:400]
    return ''


def summarize_sessions(sessions: list[dict], files: list[str],
                       max_chars: int = MAX_SUMMARY_CHARS) -> tuple[str, list[str]]:
    """按文件路径过滤相关 session，返回 (摘要文本, 命中的 task_id 列表)。

    匹配策略：图灵 session 的 parts 文本 / prompt 里出现目标文件路径（全路径或 basename）
    即视为「图灵曾接触该文件」。fake_turing 数据无 tool part，靠 reasoning/text 提取；
    真实图灵 tool part 的入参（读文件路径）也由 _part_text 一并解析。
    """
    if not files or not sessions:
        return ('', [])
    patterns: list[str] = []
    for f in files:
        patterns.append(re.escape(f))
        base = f.rsplit('/', 1)[-1]
        if base and base != f:
            patterns.append(re.escape(base))
    rx = re.compile('|'.join(patterns))

    chunks: list[str] = []
    hit_tasks: list[str] = []
    total = 0
    for s in sessions:
        msg = s.get('session') or {}
        parts = msg.get('parts') or []
        blob = '\n'.join([s.get('prompt') or ''] + [_part_text(p) for p in parts])
        if not rx.search(blob):
            continue
        tid = s.get('task_id')
        if tid:
            hit_tasks.append(tid)
        for p in parts:
            txt = _part_text(p)
            if not txt:
                continue
            chunk = f"[{p.get('type')}] {txt}"
            chunks.append(chunk)
            total += len(chunk) + 1
            if total >= max_chars:
                break
        if total >= max_chars:
            break
    summary = '\n'.join(chunks)[:max_chars]
    return summary, hit_tasks


def filter_sessions(sessions: list[dict], files: list[str]) -> list[dict]:
    """按文件路径过滤命中的完整 session（供 worker dump 给 agent，避免全量读爆 context）。

    匹配策略同 summarize_sessions（session 的 prompt+parts 文本命中文件全路径或 basename）。
    """
    if not files or not sessions:
        return []
    patterns: list[str] = []
    for f in files:
        patterns.append(re.escape(f))
        base = f.rsplit('/', 1)[-1]
        if base and base != f:
            patterns.append(re.escape(base))
    if not patterns:
        return []
    rx = re.compile('|'.join(patterns))
    out: list[dict] = []
    for s in sessions:
        msg = s.get('session') or {}
        parts = msg.get('parts') or []
        blob = '\n'.join([s.get('prompt') or ''] + [_part_text(p) for p in parts])
        if rx.search(blob):
            out.append(s)
    return out


INSTRUCTION_TEMPLATE = """你是漏洞挖掘复盘专家。图灵（基于 opencode 的 agent）扫描被测项目时**漏报**了下面这个漏洞（Ground Truth 有、图灵没报出）。请读取相关源码与图灵的挖掘记录，分析图灵为何漏挖，并给出可操作的优化建议。

## 被漏报的漏洞
- 漏洞类型: {vuln_type}
- 漏洞位置: {location}
- source: {source}
- sink: {sink}
- 描述: {description}
- 相关文件: {files}

## 可用资源（当前工作目录下，可自由 read/grep）
- `./repo/` ：被测项目源码
- `./sessions.json` ：图灵本次扫描的**完整** opencode 挖掘记录（opencode message 格式，parts 含 reasoning/text/tool；用 grep 搜文件路径/basename 可定位图灵对该文件的处理）

## 任务
1. 读取 `./repo/` 中 source/sink 对应源码，理解漏洞。
2. 在 `./sessions.json` 中检索图灵对这些文件的处理记录（grep 文件名）。
3. 从挖掘路径/推理/工具使用角度分析**图灵为何漏挖此漏洞**，输出 markdown：
   ## 漏挖原因（结合读到的具体代码行/记录）
   ## 优化建议（可落地，帮助图灵自我迭代）

注意：只做分析，不要修改任何文件。
"""


def _fmt_loc(loc: dict | None) -> str:
    if not loc:
        return '（GT 未提供）'
    f = loc.get('file', '')
    line = loc.get('line')
    return f"{f}{':' + str(line) if line else ''}" or '（未提供）'


def build_instruction(fn: dict) -> str:
    """构造给 opencode agent 的 instruction（漏洞信息 + 指向 ./repo 与 ./sessions.json）。"""
    files = relevant_files(fn)
    return INSTRUCTION_TEMPLATE.format(
        vuln_type=fn.get('vuln_type', '') or '（未知）',
        location=_fmt_loc(fn.get('location') or {}),
        source=_fmt_loc(fn.get('source')),
        sink=_fmt_loc(fn.get('sink')),
        description=fn.get('description', '') or '（无）',
        files=', '.join(files) or '（无）',
    )


async def analyze_one(fn: dict, workdir: str, jcfg: dict, sample_id: str) -> dict:
    """跑 opencode agent 分析单个 FN 漏洞（workdir 含 repo/ + sessions.json）。

    jcfg: {api_url, api_key, model_id}（judge 全局配置）。
    返回 {gt_id, advice?, related_files, status, error?, ts}。
    """
    gt_id = fn.get('gt_id')
    files = relevant_files(fn)
    instruction = build_instruction(fn)

    # 规避本机 socks 代理：opencode 经 bridge → OpenAICompatibleAPI 调 judge，httpx 默认
    # trust_env=True 会读 socks 代理报 "Unknown scheme for proxy URL socks://"。构造 client 前 unset。
    _PROXY_KEYS = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')
    saved_proxy = {k: os.environ.pop(k, None) for k in _PROXY_KEYS}
    try:
        api = OpenAICompatibleAPI(model_name=jcfg['model_id'], base_url=jcfg['api_url'], api_key=jcfg['api_key'])
        model = Model(api=api, config=GenerateConfig(max_tokens=4096, temperature=0.0))
        config = ExternalAgentConfig(
            framework='opencode',
            kwargs={'model_name': jcfg['model_id'], 'auto_install': True, 'home_override': ''},
            environment='local', environment_extra={'working_dir': workdir}, timeout=900.0,
        )
        sample = Sample(input=instruction, id=sample_id)
        result = await asyncio.to_thread(run_external_agent, config=config, model=model, sample=sample)
        advice = (result.output.message.text or '').strip()
    except Exception as e:
        logger.error(f'[fn_advisor] gt_id={gt_id} opencode agent 失败: {e}', exc_info=True)
        advice = f'[ERROR] opencode agent 失败: {e}'
    finally:
        os.environ.update({k: v for k, v in saved_proxy.items() if v})

    out: dict[str, Any] = {'gt_id': gt_id, 'related_files': files, 'ts': int(time.time())}
    if not advice or advice.startswith('[ERROR]'):
        out['status'] = 'error'
        out['error'] = advice or 'opencode 返回空'
        logger.warning(f'[fn_advisor] gt_id={gt_id} 分析失败: {out["error"]}')
    else:
        out['status'] = 'ok'
        out['advice'] = advice
        logger.info(f'[fn_advisor] gt_id={gt_id} opencode 分析完成 (相关文件={len(files)})')
    return out
