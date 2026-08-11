"""FN 漏报 LLM-as-judge 路径分析。

针对图灵漏报的漏洞（GT 有、图灵没报），拉取该 job 的全部 opencode 挖掘 session，
按漏洞的 source/sink 文件路径定位图灵曾接触相关文件的 session 片段，交给 LLM
复盘「图灵为何没能挖掘出这个漏洞」，输出可操作的优化建议（帮助图灵自我迭代）。

入口：``analyze_one(fn, project_id, job_id, client, judge)``（async）。
由 reports 蓝图 ``/fn-advice`` 端点调用，结果缓存到 outputs/<task>/fn_advice/<dataset>.json。
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from evalscope.api.messages import ChatMessageSystem, ChatMessageUser
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


SYSTEM_PROMPT = (
    '你是资深漏洞挖掘复盘专家。下面会给你一个被漏报的漏洞（Ground Truth，扫描器图灵未报出），'
    '以及图灵（基于 opencode 的 agent）在本次扫描中接触该漏洞相关文件时的挖掘记录摘要。'
    '你的任务是从挖掘路径、推理过程、工具使用等角度分析图灵为什么没能挖出这个漏洞，'
    '并给出具体、可操作的优化建议，帮助图灵自我迭代。'
    '用中文，以 markdown 输出，分「## 漏挖原因」和「## 优化建议」两部分，'
    '原因要结合记录里的具体行为，建议要可落地。'
)

USER_TEMPLATE = """# 漏洞挖掘复盘任务

## 被漏报的漏洞（图灵未报出）
- 漏洞类型: {vuln_type}
- 漏洞位置: {location}
- source: {source}
- sink: {sink}
- 描述: {description}

## 图灵本次扫描接触相关文件的挖掘记录摘要（opencode session）
> 相关文件: {files}
---
{summary}
---

请基于上述记录分析：图灵为何没能挖掘出这个漏洞？给出漏挖原因与优化建议。
"""


def _fmt_loc(loc: dict | None) -> str:
    if not loc:
        return '（GT 未提供）'
    f = loc.get('file', '')
    line = loc.get('line')
    return f"{f}{':' + str(line) if line else ''}" or '（未提供）'


def build_prompt(fn: dict, summary: str, files: list[str]) -> list:
    loc = fn.get('location') or {}
    loc_str = _fmt_loc(loc)
    user = USER_TEMPLATE.format(
        vuln_type=fn.get('vuln_type', '') or '（未知）',
        location=loc_str,
        source=_fmt_loc(fn.get('source')),
        sink=_fmt_loc(fn.get('sink')),
        description=fn.get('description', '') or '（无）',
        files=', '.join(files) or '（无）',
        summary=summary or '（图灵在本次扫描的 session 记录中未提及该漏洞相关文件——可能根本未触达）',
    )
    return [ChatMessageSystem(content=SYSTEM_PROMPT), ChatMessageUser(content=user)]


async def analyze_one(fn: dict, project_id: str, job_id: str, client: Any, judge: Any) -> dict:
    """分析单个 FN 漏洞：拉 sessions → 按文件过滤 → LLM 复盘 → 返回结果 dict。

    client: TuringClient 实例（需已 login）；judge: LLMJudge 实例。
    返回 {gt_id, advice, related_files, related_sessions, status, error?, ts}。
    """
    files = relevant_files(fn)
    gt_id = fn.get('gt_id')
    sessions_resp = await client.get_job_sessions(project_id, job_id)
    sessions = (sessions_resp or {}).get('sessions') or []
    summary, hit_tasks = summarize_sessions(sessions, files)
    messages = build_prompt(fn, summary, files)
    advice = judge.judge(messages=messages)

    result: dict[str, Any] = {
        'gt_id': gt_id,
        'related_files': files,
        'related_sessions': len(hit_tasks),
        'ts': int(time.time()),
    }
    if not advice or advice.startswith('[ERROR]'):
        result['status'] = 'error'
        result['error'] = advice or 'LLM 返回空'
        logger.warning(f'[fn_advisor] gt_id={gt_id} LLM 分析失败: {result["error"]}')
    else:
        result['status'] = 'ok'
        result['advice'] = advice
        logger.info(f'[fn_advisor] gt_id={gt_id} 分析完成 (相关文件={len(files)} 相关session={len(hit_tasks)})')
    return result
