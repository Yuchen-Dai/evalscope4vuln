"""漏洞挖掘轨迹展示适配：图灵 opencode session → 前端 trajectory 数据。

把图灵该 job 的 sessions（opencode message {info, parts}）按 finding 关联到各阶段
（mine/verify/detect），并把每个 session 的 parts 适配成 step[]（仿 index.html 的
step 节点：thought/tool/finding/conclusion 着色），加基础统计（步数/工具/耗时/token）。

入口：``sessions_to_trajectory(sessions, task_id, finding_id, vuln_type)`` →
``{stages:{mine/verify/detect: [{task_id, task_type, steps[]}]}, stats}``。
由 reports 蓝图 ``GET /trace/for-finding`` 调用。
"""
from __future__ import annotations

import json
from typing import Any

# step 类型 → 中文标签（前端 legend 用）
STEP_LABELS = {
    'thought': '思考',
    'tool': '工具',
    'finding': '入库',
    'conclusion': '结论',
    'text': '输出',
}

# 判定「结论」的关键词（text part 含这些 → conclusion step）
_CONCLUSION_KEYS = ('结论', '确认', '误报', 'FALSE POSITIVE', '总结', '完成总结', '探测记录', '发现 ID')


def _first_line(txt: str, n: int = 90) -> str:
    """取第一行（或前 n 字）作为 step summary。"""
    if not txt:
        return ''
    line = txt.split('\n', 1)[0].strip()
    return (line[:n] + '…') if len(line) > n else line


def _is_conclusion(txt: str) -> bool:
    s = txt.strip()
    if not s:
        return False
    return any(k in s for k in _CONCLUSION_KEYS)


def _part_time_ms(part: dict) -> int | None:
    t = part.get('time')
    if isinstance(t, dict):
        return t.get('start') or t.get('created')
    if isinstance(t, (int, float)):
        return int(t)
    return None


def _tool_name(part: dict) -> str:
    """从 tool part 取工具名（opencode 真实图灵字段：tool / name）。"""
    return str(part.get('tool') or part.get('name') or 'tool')


def _is_finding_submit(part: dict) -> bool:
    """submit_artifact(finding) → finding step。"""
    name = _tool_name(part).lower()
    if 'submit_artifact' not in name and 'submit' not in name:
        return False
    payload = part.get('input') or part.get('args') or part
    s = json.dumps(payload, ensure_ascii=False)
    return 'finding' in s.lower()


def _tool_detail(part: dict) -> str:
    """tool part 的完整 Input/Output（折叠展示）。"""
    name = _tool_name(part)
    inp = part.get('input') or part.get('args')
    out = part.get('output') or part.get('result')
    parts = [f'Tool: {name}']
    if inp is not None:
        parts.append('Input:\n' + json.dumps(inp, ensure_ascii=False, indent=2)[:4000])
    if out is not None:
        parts.append('Output:\n' + (out if isinstance(out, str) else json.dumps(out, ensure_ascii=False, indent=2))[:4000])
    return '\n\n'.join(parts)


def _tool_summary(part: dict, name: str) -> str:
    """tool step 一行摘要（name + 关键入参如文件路径）。"""
    inp = part.get('input') or part.get('args') or {}
    if isinstance(inp, dict):
        # 常见读文件类工具的路径字段
        for k in ('filePath', 'path', 'file', 'pattern', 'name'):
            v = inp.get(k)
            if v:
                return f'{name}: {v}'
    return name


def session_to_steps(session: dict) -> list[dict]:
    """opencode message {info, parts} → step[]（仿 index.html step 节点）。

    part 映射：reasoning→thought；tool→tool（submit_artifact(finding)→finding）；
    含结论关键词的 text→conclusion；其余 text→text；patch→tool(patch)；step-start/finish 跳过。
    每个 step: {id, type, title, summary, detail, time, tool?}。
    """
    msg = session.get('session') or {}
    parts = msg.get('parts') or []
    steps: list[dict] = []
    for i, p in enumerate(parts):
        if not isinstance(p, dict):
            continue
        t = p.get('type')
        time = _part_time_ms(p)
        sid = f's{i}'
        if t == 'reasoning':
            txt = p.get('text', '') or ''
            steps.append({'id': sid, 'type': 'thought', 'title': '思考',
                          'summary': _first_line(txt), 'detail': txt, 'time': time})
        elif t == 'text':
            txt = p.get('text', '') or ''
            stype = 'conclusion' if _is_conclusion(txt) else 'text'
            steps.append({'id': sid, 'type': stype,
                          'title': '结论' if stype == 'conclusion' else '输出',
                          'summary': _first_line(txt), 'detail': txt, 'time': time})
        elif t == 'tool':
            name = _tool_name(p)
            stype = 'finding' if _is_finding_submit(p) else 'tool'
            steps.append({'id': sid, 'type': stype, 'title': name, 'tool': name,
                          'summary': _tool_summary(p, name), 'detail': _tool_detail(p), 'time': time})
        elif t == 'patch':
            detail = json.dumps(p.get('patch') or p, ensure_ascii=False)[:3000]
            steps.append({'id': sid, 'type': 'tool', 'title': 'patch', 'tool': 'patch',
                          'summary': '代码修改', 'detail': detail, 'time': time})
        # step-start / step-finish: 边界，不生成 step
    return steps


def stage_for_session(session: dict) -> str:
    """task_type → 阶段名（mine/verify/detect/preprocess/deepmine/other）。"""
    tt = (session.get('task_type') or '').lower()
    if tt.startswith('mining'):
        return 'mine'
    if tt.startswith('validation'):
        return 'verify'
    if 'detection' in tt:
        return 'detect'
    if 'classification' in tt:
        return 'preprocess'
    if 'horizontal' in tt:
        return 'deepmine'
    return 'other'


def _session_stats(session: dict) -> dict:
    """从 session.info 取耗时/ token。"""
    info = (session.get('session') or {}).get('info') or {}
    time_obj = info.get('time') or {}
    dur_ms = None
    if isinstance(time_obj, dict) and time_obj.get('created') and time_obj.get('completed'):
        dur_ms = time_obj['completed'] - time_obj['created']
    tokens = info.get('tokens') or {}
    return {
        'duration_ms': dur_ms,
        'tokens_input': tokens.get('input', 0) if isinstance(tokens, dict) else 0,
        'tokens_output': tokens.get('output', 0) if isinstance(tokens, dict) else 0,
    }


def sessions_to_trajectory(sessions: list[dict], task_id: str | None,
                           finding_id: str | None, vuln_type: str | None) -> dict:
    """关联 finding 到各阶段 session + 适配 step + 统计。

    关联：mine = session.task_id == task_id（精确 1:1）；
          verify = task_type/prompt 含 finding_id（validation_<finding_id>）；
          detect = task_type 含 taint_detection_*_<vuln_type>（粗关联，该漏洞类型的批量探测）。
    返回 {stages:{mine/verify/detect: [{task_id, task_type, session_id, steps[]}]}, stats:{...}}。
    """
    stages: dict[str, list[dict]] = {'mine': [], 'verify': [], 'detect': []}
    all_steps: list[dict] = []
    total_input = total_output = 0
    total_dur_ms = 0
    dur_count = 0
    tool_counter: dict[str, int] = {}

    for s in sessions or []:
        stage = stage_for_session(s)
        matched = False
        if stage == 'mine' and task_id and s.get('task_id') == task_id:
            matched = True
        elif stage == 'verify' and finding_id:
            hay = (s.get('task_type') or '') + ' ' + (s.get('prompt') or '')
            if finding_id in hay:
                matched = True
        elif stage == 'detect' and vuln_type:
            if vuln_type.lower() in (s.get('task_type') or '').lower():
                matched = True
        if not matched:
            continue

        steps = session_to_steps(s)
        stages[stage].append({
            'task_id': s.get('task_id'),
            'task_type': s.get('task_type'),
            'session_id': s.get('session_id'),
            'steps': steps,
        })
        all_steps.extend(steps)
        sstat = _session_stats(s)
        total_input += sstat['tokens_input']
        total_output += sstat['tokens_output']
        if sstat['duration_ms']:
            total_dur_ms += sstat['duration_ms']
            dur_count += 1
        for st in steps:
            if st['type'] == 'tool':
                tool_counter[st.get('tool', 'tool')] = tool_counter.get(st.get('tool', 'tool'), 0) + 1

    stats = {
        'total_steps': len(all_steps),
        'tool_calls': sum(1 for s in all_steps if s['type'] == 'tool'),
        'thoughts': sum(1 for s in all_steps if s['type'] == 'thought'),
        'findings': sum(1 for s in all_steps if s['type'] == 'finding'),
        'conclusions': sum(1 for s in all_steps if s['type'] == 'conclusion'),
        'duration_ms': total_dur_ms if dur_count else None,
        'tokens_input': total_input,
        'tokens_output': total_output,
        'tool_distribution': dict(sorted(tool_counter.items(), key=lambda x: -x[1])),
    }
    return {'stages': stages, 'stats': stats}
