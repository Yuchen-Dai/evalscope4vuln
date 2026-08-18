"""FN 漏报路径分析（opencode agent）。

针对图灵漏报的漏洞（GT 有、图灵没报），给 opencode agent 一个 workdir（被测源码
`repo/` + 图灵**全量**挖掘记录 `sessions.json` + 索引 `sessions_index.jsonl`），让它
自己 read/grep 真实代码与记录、迭代推理，输出「图灵为何漏挖」的原因与优化建议，
并重构该漏洞相关的挖掘轨迹时间线、标出中断点（帮助图灵自我迭代）。

结果回传双通道（执行与查看解耦）：
- 主通道：agent 经 MCP 工具 `submit_result`（fn_result_sink.py，stdio server）把结构化
  结论原子写进 `<fn_advice>/.mcp/<gt_id>.json` staging —— 增量可见、超时不丢、手动跑
  opencode 也能被平台读到；
- 兜底：解析最终回复末尾的 ```json 块（extract_structured_advice）。
两条通道由 merge_agent_results 合并（staging 优先、stdout 回填）。

opencode 经 evalscope 的 run_external_agent + bridge（Responses→ChatCompletions 翻译）
驱动，judge 配置（api_url/model_id/api_key）经 OpenAICompatibleAPI → opencode。

入口：``analyze_one(fn, workdir, jcfg, sample_id, sink=None)``（async）。
worker（fn_advice_runner）建共享 workdir（解压源码 + dump 全量 sessions 与索引）后逐个 FN 调用。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from typing import Any, Optional

from evalscope.agent.external import ExternalAgentConfig
from evalscope.agent.external.adapter import run_external_agent
from evalscope.api.dataset import Sample
from evalscope.api.model import GenerateConfig, Model
from evalscope.benchmarks.vuln_scan.analysis.fn_result_sink import sanitize_gt_id
from evalscope.benchmarks.vuln_scan.analysis.trace_view import stage_for_session
from evalscope.models.openai_compatible import OpenAICompatibleAPI
from evalscope.utils.logger import get_logger

logger = get_logger()

# 索引约束：每 session 摘要的文件数上限 / prompt 截断长度
MAX_INDEX_FILES = 10
MAX_PROMPT_HEAD = 120

# opencode agent 超时（全量 sessions 分析比按文件过滤版更重，从 900s 上调）
AGENT_TIMEOUT_S = 1500.0


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


# ---- 全量 sessions 索引（供 agent grep 定位，避免直读上百 MB 的 sessions.json）----


def _part_files(part: dict) -> list[str]:
    """best-effort 提取单个 part 涉及的文件路径（tool 入参 / patch 文件列表）。"""
    ptype = part.get('type')
    if ptype == 'patch':
        files = part.get('files')
        if isinstance(files, list):
            return [f for f in files if isinstance(f, str) and f]
        return []
    if ptype != 'tool':
        return []
    inp = part.get('input') or part.get('args')
    if not isinstance(inp, dict):
        return []
    out: list[str] = []
    for key in ('filePath', 'path', 'file'):
        v = inp.get(key)
        # 跳过目录值（grep 的 path 常传目录，以 / 结尾或无扩展名的锚点根）
        if isinstance(v, str) and v and not v.endswith('/'):
            out.append(v)
    return out


def _session_files(session: dict, limit: int = MAX_INDEX_FILES) -> list[str]:
    """session 全部 parts 涉及文件（去重保序，截断到 limit）。"""
    files: list[str] = []
    seen: set[str] = set()
    for part in (session.get('session') or {}).get('parts') or []:
        if not isinstance(part, dict):
            continue
        for f in _part_files(part):
            if f in seen:
                continue
            seen.add(f)
            files.append(f)
            if len(files) >= limit:
                return files
    return files


def _session_tool_stats(session: dict) -> tuple[int, dict[str, int]]:
    """session 的工具调用统计：(总数, {工具名: 次数})。"""
    total = 0
    tools: dict[str, int] = {}
    for part in (session.get('session') or {}).get('parts') or []:
        if not isinstance(part, dict) or part.get('type') != 'tool':
            continue
        name = part.get('tool') or part.get('name') or 'unknown'
        total += 1
        tools[name] = tools.get(name, 0) + 1
    return total, tools


def build_sessions_index(sessions: list[dict]) -> list[dict]:
    """全量 sessions → 每 session 一行的紧凑索引（worker dump 成 sessions_index.jsonl）。

    字段：task_id/session_id/task_type/stage（复用 trace_view 阶段规则）/父子与 finding
    关联/涉及文件（截断）/工具统计/prompt 头部摘要。agent 先 grep 此文件定位相关
    session，再持 task_id 到全量 sessions.json 分窗精读。
    """
    index: list[dict] = []
    for s in sessions or []:
        if not isinstance(s, dict):
            continue
        tool_calls, tools = _session_tool_stats(s)
        prompt_head = re.sub(r'\s+', ' ', (s.get('prompt') or '').strip())[:MAX_PROMPT_HEAD]
        index.append({
            'task_id': s.get('task_id'),
            'session_id': s.get('session_id'),
            'task_type': s.get('task_type'),
            'stage': stage_for_session(s),
            'parent_task_id': s.get('parent_task_id'),
            'finding_ids': s.get('finding_ids'),
            'detection_ids': s.get('detection_ids'),
            'status': s.get('status'),
            'created_at': s.get('created_at'),
            'files': _session_files(s),
            'tool_calls': tool_calls,
            'tools': tools,
            'prompt_head': prompt_head,
        })
    return index


INSTRUCTION_TEMPLATE = """你是漏洞挖掘复盘专家。图灵（基于 opencode 的 agent）扫描被测项目时**漏报**了下面这个漏洞（Ground Truth 有、图灵没报出）。请基于被测源码与图灵的**全量**挖掘记录，重构该漏洞相关的挖掘轨迹、定位图灵在哪一步中断导致漏挖，并给出可操作的优化建议。

## 被漏报的漏洞
- 漏洞类型: {vuln_type}
- 漏洞位置: {location}
- source: {source}
- sink: {sink}
- 描述: {description}
- 相关文件: {files}

## 可用资源（当前工作目录下，可自由 read/grep）
- `./repo/` ：被测项目源码
- `./sessions_index.jsonl` ：图灵本次扫描**全量** session 的索引，每行一个 session 摘要（task_id/task_type/stage/涉及文件/工具统计/prompt 摘要等字段）。**先用它 grep 文件路径/basename/漏洞类型关键词定位相关 session，记下 task_id**（一行 grep 一个 session，速度最快）
- `./sessions.json` ：图灵本次扫描的完整 opencode 挖掘记录（可能上百 MB，**禁止整体读取**）。定位到 task_id 后：`grep -n '"<task_id>"' sessions.json` 取行号，再 `sed -n 'X,Yp' sessions.json` 分窗精读该 session 的 parts（reasoning/text/tool）
- MCP 工具 `submit_result` ：分析结论的提交通道（用法见输出格式）

## 任务
1. 读取 `./repo/` 中 source/sink 对应源码，理解漏洞成因与数据流。
2. 在 `./sessions_index.jsonl` 检索图灵对这些文件/该漏洞类型的处理记录；对关键 session 用 task_id 到 `./sessions.json` 分窗精读（reasoning 看图灵的判断、tool 看它读了什么/放弃了什么）。
3. **重构挖掘轨迹时间线**：把与该漏洞相关的挖掘过程整理为按阶段（preprocess/detect/mine/deepmine/verify）的步骤序列，每步尽量标注真实 task_id/session_id 与文件位置；判断图灵在哪一步中断（从未探测该文件？探测了没挖到？挖到了当误报放弃？验证不足放弃？），中断的那一步标记为中断点。
4. 输出 markdown：
   ## 漏挖原因（结合读到的具体代码行/记录）
   ## 优化建议（可落地，帮助图灵自我迭代）

注意：只做分析，不要修改任何文件（调用 submit_result 工具除外）。
"""

# 输出契约（追加在 INSTRUCTION_TEMPLATE 之后）：MCP submit_result 为主通道，最终回复的
# JSON 代码块为兜底通道，供 analyze_one 做 best-effort 结构化提取（extract_structured_advice）。
# 独立常量而非并入模板：模板经 .format() 渲染，JSON 花括号需转义，分开拼接更直观。
OUTPUT_CONTRACT = """

## 输出格式（必须遵守）
分析完成后，结论提交有两条通道：

1. **主通道（优先）**：调用 MCP 工具 `submit_result`，把下面结构的 JSON 对象作为参数提交。
   这是平台读取结果的主通道；提交成功后，最终回复只需简短 markdown 总结，无需重复 JSON。
   可多次调用（补充修正后重新提交，后一次覆盖前一次）。
2. **兜底通道**：仅当 `submit_result` 工具不可用或调用失败时，最终回复必须以 JSON 代码块
   结尾（```json 开头、``` 结束）承载同一结构。

JSON 结构与字段如下（字段名固定，值用中文，stages/stage 取给定枚举值）：

```json
{
  "category": "归因分类，从 探测阶段遗漏/挖掘深度不足/验证误判/知识库缺失/其他 中选一个",
  "stages": ["涉及阶段，从 preprocess/detect/mine/deepmine/verify 中选与漏挖相关的，可多个"],
  "reasoning": "漏挖原因分析（2-4 句，引用读到的具体代码行/记录）",
  "suggestions": ["具体可执行的改进建议，逐条"],
  "summary": "一句话结论",
  "trace": {
    "steps": [
      {"id": "s0", "stage": "detect", "type": "briefing", "title": "探测任务开场", "summary": "一句话概括", "detail": "依据：引用 task_id 的记录片段或代码行", "task_id": "T-123", "session_id": "ses_x", "file": "a/Foo.java", "line": 10},
      {"id": "s5", "stage": "mine", "type": "dead_end", "title": "放弃该路径", "summary": "图灵判定误报后放弃", "detail": "...", "task_id": "T-130"}
    ],
    "breakpoint": {"stage": "mine", "step_id": "s5", "reason": "图灵在这一步中断导致漏挖的具体原因", "category": "挖掘深度不足"},
    "story": ["[探测] 定位到候选入口", "[挖掘] 判定误报后放弃 ✗ 中断"]
  }
}
```

trace.steps 要求：8-20 步、按挖掘时序排列、覆盖 5 阶段中与该漏洞相关的阶段；type 从
thought（模型思考）/tool（工具调用）/finding（确认入库）/conclusion（阶段结论）/briefing（阶段任务开场）/dead_end（中断、放弃、死胡同）中选；**中断的那一步必须标 dead_end，且其 id 与 breakpoint.step_id 对应**；task_id/session_id 填真实记录里的值（纯推断的步骤可省略这两个字段，但 detail 要写明推断依据）。

要求：JSON 必须是合法 JSON（无注释、无尾逗号、字符串内不要换行转义错误）。只做分析，不要修改任何文件（调用 submit_result 除外）。
"""


def _fmt_loc(loc: dict | None) -> str:
    if not loc:
        return '（GT 未提供）'
    f = loc.get('file', '')
    line = loc.get('line')
    return f"{f}{':' + str(line) if line else ''}" or '（未提供）'


def build_instruction(fn: dict) -> str:
    """构造给 opencode agent 的 instruction（漏洞信息 + 指向 ./repo 与 ./sessions.json + 输出契约）。"""
    files = relevant_files(fn)
    return INSTRUCTION_TEMPLATE.format(
        vuln_type=fn.get('vuln_type', '') or '（未知）',
        location=_fmt_loc(fn.get('location') or {}),
        source=_fmt_loc(fn.get('source')),
        sink=_fmt_loc(fn.get('sink')),
        description=fn.get('description', '') or '（无）',
        files=', '.join(files) or '（无）',
    ) + OUTPUT_CONTRACT


# ```json ... ``` 代码块（非贪婪单块；契约要求 JSON 在末尾，匹配多个时先试最后一个）
_JSON_FENCE_RE = re.compile(r'```json\s*(.*?)\s*```', re.DOTALL)
# 裸 {...}：首个 { 到最后一个 }（首尾配对最宽容，容忍中间字符串里的花括号错位）
_JSON_BARE_RE = re.compile(r'\{.*\}', re.DOTALL)

# 结构化字段清洗：保留的顶层键 + 各字段类型
_STRUCT_STRING_KEYS = ('category', 'reasoning', 'summary')
_STRUCT_LIST_KEYS = ('stages', 'suggestions')

# trace 清洗约束：step 类型/阶段枚举 + detail 截断
_TRACE_STEP_TYPES = ('thought', 'tool', 'finding', 'conclusion', 'text', 'dead_end', 'briefing')
_TRACE_STAGES = ('preprocess', 'detect', 'mine', 'deepmine', 'verify')
_TRACE_DETAIL_MAX = 4000


def _sanitize_trace_steps(raw: Any) -> Optional[list[dict]]:
    """清洗 trace.steps：白名单键、非法 type 归一为 text、detail 截断、title 兜底。

    非 list / 清洗后为空 → None（调用方不写 trace 键，回退旧行为）。
    """
    if not isinstance(raw, list) or not raw:
        return None
    steps: list[dict] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        step_type = item.get('type')
        step: dict = {
            'id': str(item.get('id') or f's{i}'),
            'type': step_type if step_type in _TRACE_STEP_TYPES else 'text',
            'title': str(item.get('title') or item.get('summary') or f'step {i}'),
        }
        for k in ('stage', 'summary', 'tool', 'file', 'task_id', 'session_id'):
            v = item.get(k)
            if isinstance(v, str) and v.strip():
                step[k] = v.strip()
        detail = item.get('detail')
        if isinstance(detail, str) and detail.strip():
            step['detail'] = detail.strip()[:_TRACE_DETAIL_MAX]
        for k in ('time', 'line'):
            v = item.get(k)
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                step[k] = int(v)
        steps.append(step)
    return steps or None


def _sanitize_breakpoint(raw: Any) -> Optional[dict]:
    """清洗 trace.breakpoint：stage 钳制到 5 阶段枚举（非法 → 整体丢弃，reason 不孤立保留）。"""
    if not isinstance(raw, dict) or raw.get('stage') not in _TRACE_STAGES:
        return None
    bp: dict = {'stage': raw.get('stage')}
    for k in ('step_id', 'reason', 'category'):
        v = raw.get(k)
        if isinstance(v, str) and v.strip():
            bp[k] = v.strip()
    return bp


def extract_structured_advice(text: str) -> dict | None:
    """从 agent 输出 best-effort 提取结构化结论（```json 块优先，裸 {...} 兜底）。

    json.loads 失败 / 非 dict / 无任何已知字段 → 放弃返回 None（调用方回退纯文本）。
    已知字段按类型清洗（字符串 strip、列表元素转字符串），噪声键丢弃。
    """
    if not text:
        return None
    # 候选：所有 ```json 块（后优先，契约要求末尾输出）+ 裸 {...} 兜底
    candidates: list[str] = [m.group(1) for m in _JSON_FENCE_RE.finditer(text)]
    candidates.reverse()
    bare = _JSON_BARE_RE.search(text)
    if bare:
        candidates.append(bare.group(0))
    for cand in candidates:
        try:
            obj = json.loads(cand)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        out: dict = {}
        for k in _STRUCT_STRING_KEYS:
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                out[k] = v.strip()
            elif v is not None and not isinstance(v, (dict, list)) and str(v).strip():
                out[k] = str(v).strip()
        for k in _STRUCT_LIST_KEYS:
            v = obj.get(k)
            if isinstance(v, list):
                items = [str(x).strip() for x in v if str(x).strip()]
                if items:
                    out[k] = items
            elif isinstance(v, str) and v.strip():
                # agent 把数组写成单个字符串：按逗号/分号切
                items = [s.strip() for s in re.split(r'[,;，；]', v) if s.strip()]
                if items:
                    out[k] = items
        trace_obj = obj.get('trace')
        if isinstance(trace_obj, dict):
            steps = _sanitize_trace_steps(trace_obj.get('steps'))
            if steps:
                trace_out: dict = {'steps': steps}
                bp = _sanitize_breakpoint(trace_obj.get('breakpoint'))
                if bp:
                    trace_out['breakpoint'] = bp
                story = trace_obj.get('story')
                if isinstance(story, list):
                    trace_out['story'] = [str(x).strip() for x in story if str(x).strip()]
                out['trace'] = trace_out
        if out:
            return out
    return None


# staging（MCP 写回）payload 里的平台元数据键（合并结构化结论时剔除）
_STAGING_META_KEYS = ('gt_id', 'status', 'source', 'ts')


def merge_agent_results(agent_out: dict, staging: Optional[dict]) -> dict:
    """合并 MCP staging 与 stdout 提取结果（纯函数）。

    - staging（agent 经 submit_result 主动提交）作为结构化结论基底，键冲突时优先；
      agent_out.advice_structured 只回填 staging 缺失的键；
    - advice（markdown 叙事）恒取 agent_out；agent 进程异常（超时等）但 staging 有效时，
      由 staging 的 summary/reasoning 合成占位叙事 —— 超时不丢已提交结论；
    - status：任一通道有内容即 ok，双失败 error。
    """
    staging = staging if isinstance(staging, dict) else None
    base: dict = {
        'gt_id': (staging or {}).get('gt_id') or agent_out.get('gt_id'),
        'related_files': agent_out.get('related_files') or [],
        'ts': max(int((staging or {}).get('ts') or 0), int(agent_out.get('ts') or 0)),
    }
    structured: dict = {}
    if staging:
        structured.update({k: v for k, v in staging.items() if k not in _STAGING_META_KEYS})
    agent_struct = agent_out.get('advice_structured')
    if isinstance(agent_struct, dict):
        for k, v in agent_struct.items():
            structured.setdefault(k, v)

    advice = agent_out.get('advice')
    advice_ok = bool(advice) and not str(advice).startswith('[ERROR]')
    if not structured and not advice_ok:
        base['status'] = 'error'
        base['error'] = agent_out.get('error') or str(advice or 'opencode 未产出结论')
        return base

    base['status'] = 'ok'
    if structured:
        base['advice_structured'] = structured
    if advice_ok:
        base['advice'] = advice
    else:
        # agent 进程未正常结束但 staging 已救回结论：合成占位叙事
        parts = ['# 漏报分析（MCP 提交；opencode 进程未正常结束）']
        if structured.get('summary'):
            parts.append(f'## 结论\n\n{structured["summary"]}')
        if structured.get('reasoning'):
            parts.append(f'## 原因\n\n{structured["reasoning"]}')
        if agent_out.get('error'):
            parts.append(f'> opencode 异常: {agent_out["error"]}')
        base['advice'] = '\n\n'.join(parts)
    return base


def _sink_mcp_config(sink: dict) -> dict:
    """opencode.json 的 mcp 配置（拉起 fn_result_sink，env 传 staging 目标）。"""
    return {
        'fn-result-sink': {
            'type': 'local',
            'command': [sys.executable, '-m', 'evalscope.benchmarks.vuln_scan.analysis.fn_result_sink'],
            'environment': {
                'FN_SINK_DIR': sink['dir'],
                'FN_SINK_GT_ID': sink['gt_id']
            },
            'enabled': True,
            'timeout': 10000,
        }
    }


def read_staging(sink: Optional[dict]) -> Optional[dict]:
    """读 MCP staging 文件（不存在/损坏 → None）。公开供 runner 在 agent 异常路径兜底复用。"""
    if not sink:
        return None
    path = os.path.join(sink['dir'], '.mcp', f'{sanitize_gt_id(sink["gt_id"])}.json')
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


async def analyze_one(fn: dict, workdir: str, jcfg: dict, sample_id: str, sink: Optional[dict] = None) -> dict:
    """跑 opencode agent 分析单个 FN 漏洞（workdir 含 repo/ + 全量 sessions.json + 索引）。

    jcfg: {api_url, api_key, model_id}（judge 全局配置）。
    sink: {'dir': <outputs fn_advice 目录>, 'gt_id': <gt_id>}；非 None 时给 opencode 挂
    fn-result-sink MCP（agent 经 submit_result 把结论写 staging），结束后与 stdout 提取
    结果合并（merge_agent_results）—— 超时/异常也不丢已提交的结论。
    返回 {gt_id, advice?, advice_structured?(含 trace?), related_files, status, error?, ts}。
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
        # 输出契约含 trace JSON（8-20 步），max_tokens 从 4096 上调避免兜底通道截断
        model = Model(api=api, config=GenerateConfig(max_tokens=8192, temperature=0.0))
        kwargs: dict = {'model_name': jcfg['model_id'], 'auto_install': True, 'home_override': ''}
        if sink:
            kwargs['mcp_servers'] = _sink_mcp_config(sink)
        config = ExternalAgentConfig(
            framework='opencode',
            kwargs=kwargs,
            environment='local',
            environment_extra={'working_dir': workdir},
            timeout=AGENT_TIMEOUT_S,
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
        structured = extract_structured_advice(advice)
        if structured:
            out['advice_structured'] = structured
            logger.info(f'[fn_advisor] gt_id={gt_id} opencode 分析完成 (相关文件={len(files)}, 结构化提取成功)')
        else:
            logger.info(f'[fn_advisor] gt_id={gt_id} opencode 分析完成 (相关文件={len(files)}, 结构化提取失败→纯文本)')

    merged = merge_agent_results(out, read_staging(sink))
    trace = (merged.get('advice_structured') or {}).get('trace') or {}
    if trace.get('steps'):
        logger.info(f'[fn_advisor] gt_id={gt_id} 中断轨迹 steps={len(trace["steps"])}')
    return merged
