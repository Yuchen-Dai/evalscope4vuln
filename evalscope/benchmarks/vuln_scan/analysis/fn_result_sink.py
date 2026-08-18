"""FN 分析结果回传 MCP server（最小 stdio JSON-RPC 实现，无第三方依赖）。

opencode agent 分析漏报时，经 MCP 工具 ``submit_result`` 把结构化结论**主动写回**平台
输出目录（staging），平台（evalscope service）只读文件 —— 执行与查看彻底解耦：

- 增量可见：agent 调用工具的瞬间结果即落盘，无需等 opencode 进程退出；
- 超时不丢：即使 opencode 超时/崩溃，已提交的 staging 仍在；
- 手动可用：终端手动跑 opencode（同一 MCP 配置）也能被平台读到。

写入位置：``$FN_SINK_DIR/.mcp/<safe_gt_id>.json``（tmp + os.replace 原子写）。
``reports._load_fn_advice`` 读取时会叠加该目录（主文件优先，staging 补缺/更新），
``_save_fn_advice`` 读-改-写则把 staging 收编进主文件。

协议：MCP stdio transport = 按行分隔的 JSON-RPC 2.0。只实现 initialize / ping /
tools/list / tools/call 四个 method，notification（无 id）静默丢弃。

手动用法（诊断/复跑）::

    FN_SINK_DIR=/path/to/outputs/<task>/fn_advice FN_SINK_GT_ID=GT-xx \
        opencode --model openai/<model> run "..."   # opencode.json 配好本 MCP 即可

模块入口：``python -m evalscope.benchmarks.vuln_scan.analysis.fn_result_sink``
（fn_advisor.analyze_one 经 opencode.json 的 mcp.local.command 以此方式拉起）。
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import IO, Any, Optional

# MCP 协议版本（initialize 回显客户端请求的版本，不认识则回最新）
SUPPORTED_PROTOCOL_VERSIONS = ('2024-11-05', '2025-03-26', '2025-06-18')

# submit_result payload 必须至少含一个已知结论键，防 agent 提交空对象
KNOWN_RESULT_KEYS = ('category', 'reasoning', 'trace', 'suggestions', 'summary', 'stages')

# gt_id 白名单字符（其余替换为 _，防路径穿越/怪文件名）
_SAFE_GT_ID_RE = re.compile(r'[^A-Za-z0-9._-]')

SERVER_NAME = 'fn-result-sink'
SERVER_VERSION = '1.0.0'


def sanitize_gt_id(gt_id: str) -> str:
    """把 gt_id 压成安全文件名（字母数字._- 之外的字符替换为 _，空值回退 unknown）。"""
    safe = _SAFE_GT_ID_RE.sub('_', (gt_id or '').strip())
    return safe or 'unknown'


class FnResultSink:
    """封装 staging 写入目标（独立类便于单测注入 sink_dir）。"""

    def __init__(self, sink_dir: str, gt_id: str) -> None:
        self.sink_dir = sink_dir
        self.gt_id = gt_id

    @property
    def staging_path(self) -> str:
        return os.path.join(self.sink_dir, '.mcp', f'{sanitize_gt_id(self.gt_id)}.json')

    def submit(self, payload: Any) -> str:
        """校验并原子写入 staging，返回确认文本（给 agent 看的 tool result）。

        - payload 非 dict / 无任何已知结论键 → ValueError（工具层转 isError）；
        - 写入失败（目录不可写等）→ OSError 原样抛出。
        """
        if not isinstance(payload, dict):
            raise ValueError('submit_result 参数必须是 JSON 对象')
        if not any(k in payload for k in KNOWN_RESULT_KEYS):
            raise ValueError(f'submit_result 缺少结论字段（至少含 {"/".join(KNOWN_RESULT_KEYS)} 之一）')
        entry = dict(payload)
        entry.update(gt_id=self.gt_id, status='ok', source='mcp', ts=int(time.time()))

        staging_dir = os.path.dirname(self.staging_path)
        os.makedirs(staging_dir, exist_ok=True)
        tmp = f'{self.staging_path}.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(entry, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.staging_path)
        return f'staged: {self.staging_path}（平台下次读取即可见，可继续补充后重新提交覆盖）'


def _tool_descriptors() -> list[dict]:
    """tools/list 返回的工具描述（JSON Schema 输入契约）。"""
    return [{
        'name': 'submit_result',
        'description': '提交漏报分析的最终结构化结论（JSON 对象）。字段与输出契约一致：'
        'category/stages/reasoning/suggestions/summary，以及 trace（steps+breakpoint+story）。'
        '可多次调用，后一次覆盖前一次。这是平台读取结果的主通道，分析完成后必须调用。',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'category': {
                    'type': 'string',
                    'description': '归因分类'
                },
                'stages': {
                    'type': 'array',
                    'items': {
                        'type': 'string'
                    },
                    'description': '涉及阶段'
                },
                'reasoning': {
                    'type': 'string',
                    'description': '漏挖原因分析'
                },
                'suggestions': {
                    'type': 'array',
                    'items': {
                        'type': 'string'
                    },
                    'description': '优化建议'
                },
                'summary': {
                    'type': 'string',
                    'description': '一句话结论'
                },
                'trace': {
                    'type': 'object',
                    'description': '中断轨迹时间线（steps/breakpoint/story）'
                },
            },
            'additionalProperties': True,
        },
    }]


def _result(msg_id: Any, result: dict) -> dict:
    return {'jsonrpc': '2.0', 'id': msg_id, 'result': result}


def _error(msg_id: Any, code: int, message: str) -> dict:
    return {'jsonrpc': '2.0', 'id': msg_id, 'error': {'code': code, 'message': message}}


def handle_message(msg: dict, sink: FnResultSink) -> Optional[dict]:
    """处理单条 JSON-RPC 消息，返回完整响应（notification / 无需响应 → None）。纯函数可单测。"""
    msg_id = msg.get('id')
    method = msg.get('method')

    if msg_id is None:
        # notification（notifications/initialized 等）与非法消息：静默丢弃
        return None

    if method == 'initialize':
        requested = (msg.get('params') or {}).get('protocolVersion')
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[-1]
        return _result(
            msg_id, {
                'protocolVersion': version,
                'capabilities': {
                    'tools': {}
                },
                'serverInfo': {
                    'name': SERVER_NAME,
                    'version': SERVER_VERSION
                },
            }
        )
    if method == 'ping':
        return _result(msg_id, {})
    if method == 'tools/list':
        return _result(msg_id, {'tools': _tool_descriptors()})
    if method == 'tools/call':
        params = msg.get('params') or {}
        name = params.get('name')
        if name != 'submit_result':
            return _error(msg_id, -32602, f'unknown tool: {name}')
        try:
            text = sink.submit(params.get('arguments'))
            return _result(msg_id, {'content': [{'type': 'text', 'text': text}]})
        except Exception as e:  # noqa: B902  工具执行错误按 MCP 规范转 isError result
            return _result(
                msg_id, {
                    'content': [{
                        'type': 'text',
                        'text': f'submit_result failed: {e}'
                    }],
                    'isError': True
                }
            )
    return _error(msg_id, -32601, f'method not found: {method}')


def serve(stdin: IO[str], stdout: IO[str], sink: FnResultSink) -> None:
    """stdio 行循环：逐行读 JSON-RPC，写响应（None 不写），EOF 退出。"""
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            stdout.write(json.dumps(_error(None, -32700, 'parse error')) + '\n')
            stdout.flush()
            continue
        if not isinstance(msg, dict):
            stdout.write(json.dumps(_error(None, -32600, 'invalid request')) + '\n')
            stdout.flush()
            continue
        resp = handle_message(msg, sink)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + '\n')
            stdout.flush()


def main() -> int:
    """模块入口：读 FN_SINK_DIR / FN_SINK_GT_ID 环境变量并进入 stdio 循环。"""
    sink_dir = os.environ.get('FN_SINK_DIR', '')
    gt_id = os.environ.get('FN_SINK_GT_ID', '')
    if not sink_dir or not gt_id:
        sys.stderr.write('fn_result_sink: env FN_SINK_DIR and FN_SINK_GT_ID are required\n')
        return 2
    serve(sys.stdin, sys.stdout, FnResultSink(sink_dir, gt_id))
    return 0


if __name__ == '__main__':
    sys.exit(main())
