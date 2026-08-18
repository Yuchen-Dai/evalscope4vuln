"""fn_advisor 单元测试：FN 提取、相关文件、全量索引、trace 结构化提取、双通道结果合并。"""
import json

from evalscope.benchmarks.vuln_scan.analysis import fn_advisor


def test_extract_fn_schema2():
    vm = {
        'schema': 2,
        'gt': [
            {
                'gt_id': 'GT-001',
                'vuln_type': 'sql-injection',
                'location': {
                    'file': 'a/UserController.java',
                    'line': 10
                }
            },
            {
                'gt_id': 'GT-002',
                'vuln_type': 'xss',
                'location': {
                    'file': 'b/XssView.java',
                    'line': 5
                }
            },
        ],
        'type': {
            'missed_gt': ['GT-001']
        },  # GT-001 漏报
        'loc': {
            'missed_gt': ['GT-001']
        },
    }
    assert [g['gt_id'] for g in fn_advisor.extract_fn(vm)] == ['GT-001']


def test_extract_fn_schema1():
    vm = {'schema': 1, 'gt': [{'gt_id': 'G1', 'location': {'file': 'x.java'}}], 'missed_gt': ['G1']}
    assert [g['gt_id'] for g in fn_advisor.extract_fn(vm)] == ['G1']


def test_extract_fn_empty():
    assert fn_advisor.extract_fn({}) == []
    assert fn_advisor.extract_fn({'gt': [], 'type': {'missed_gt': []}}) == []


def test_relevant_files_source_sink():
    fn = {
        'location': {
            'file': 'a/Mid.java'
        },
        'source': {
            'file': 'a/Source.java',
            'line': 1
        },
        'sink': {
            'file': 'a/Sink.java',
            'line': 9
        }
    }
    assert fn_advisor.relevant_files(fn) == ['a/Source.java', 'a/Sink.java']


def test_relevant_files_fallback_location():
    fn = {'location': {'file': 'a/Mid.java', 'line': 3}}
    assert fn_advisor.relevant_files(fn) == ['a/Mid.java']


# ---- build_sessions_index ----


def _mk_session(task_id='t1', task_type='mining_sqli_a_UserController', parts=None, **extra):
    s = {
        'task_id': task_id,
        'session_id': f'ses_{task_id}',
        'task_type': task_type,
        'status': 'completed',
        'created_at': 1700000000000,
        'prompt': 'line1\nline2 挖掘任务',
        'session': {
            'parts': parts or []
        }
    }
    s.update(extra)
    return s


def test_build_sessions_index_stage_and_stats():
    parts = [
        {
            'type': 'reasoning',
            'text': '先读文件'
        },
        {
            'type': 'tool',
            'tool': 'read',
            'input': {
                'filePath': 'a/UserController.java'
            }
        },
        {
            'type': 'tool',
            'tool': 'grep',
            'args': {
                'pattern': 'queryWrapper',
                'path': 'a/'
            }
        },
        {
            'type': 'tool',
            'tool': 'read',
            'input': {
                'filePath': 'a/Util.java'
            }
        },
        {
            'type': 'text',
            'text': '结论'
        },
    ]
    idx = fn_advisor.build_sessions_index([_mk_session(parts=parts)])
    assert len(idx) == 1
    entry = idx[0]
    assert entry['task_id'] == 't1'
    assert entry['stage'] == 'mine'
    assert entry['files'] == ['a/UserController.java', 'a/Util.java']
    assert entry['tool_calls'] == 3
    assert entry['tools'] == {'read': 2, 'grep': 1}
    assert 'line1 line2' in entry['prompt_head']


def test_build_sessions_index_stages():
    sessions = [
        _mk_session('t1', 'taint_detection_java_sqli'),
        _mk_session('t2', 'validation_F-507'),
        _mk_session('t3', 'horizontal_processing'),
        _mk_session('t4', 'preprocessing'),
        _mk_session('t5', 'unknown_type'),
    ]
    stages = {e['task_id']: e['stage'] for e in fn_advisor.build_sessions_index(sessions)}
    assert stages == {'t1': 'detect', 't2': 'verify', 't3': 'deepmine', 't4': 'preprocess', 't5': 'other'}


def test_build_sessions_index_files_truncated():
    parts = [{'type': 'tool', 'tool': 'read', 'input': {'filePath': f'f{i}.java'}} for i in range(15)]
    idx = fn_advisor.build_sessions_index([_mk_session(parts=parts)])
    assert len(idx[0]['files']) == fn_advisor.MAX_INDEX_FILES


def test_build_sessions_index_empty():
    assert fn_advisor.build_sessions_index([]) == []
    assert fn_advisor.build_sessions_index([None, 'x']) == []  # 非法元素跳过


# ---- extract_structured_advice（含 trace）----


def _trace_payload(steps, breakpoint=None):
    obj = {
        'category': '挖掘深度不足',
        'stages': ['mine'],
        'reasoning': 'r',
        'suggestions': ['s1'],
        'summary': 'm',
        'trace': {
            'steps': steps
        }
    }
    if breakpoint is not None:
        obj['trace']['breakpoint'] = breakpoint
    return '分析过程……\n```json\n' + json.dumps(obj, ensure_ascii=False) + '\n```'


def test_extract_structured_advice_with_trace():
    steps = [
        {
            'id': 's0',
            'stage': 'detect',
            'type': 'briefing',
            'title': '探测开场',
            'summary': 'x',
            'task_id': 'T-1',
            'session_id': 'ses_1',
            'file': 'a/A.java',
            'line': 3
        },
        {
            'id': 's5',
            'stage': 'mine',
            'type': 'dead_end',
            'title': '放弃',
            'summary': '误判',
            'detail': 'd' * 5000
        },
    ]
    out = fn_advisor.extract_structured_advice(
        _trace_payload(steps, {
            'stage': 'mine',
            'step_id': 's5',
            'reason': '判定误报放弃'
        })
    )
    assert out is not None
    trace = out['trace']
    assert [s['id'] for s in trace['steps']] == ['s0', 's5']
    assert trace['steps'][0]['type'] == 'briefing'
    assert trace['steps'][1]['type'] == 'dead_end'
    assert len(trace['steps'][1]['detail']) == fn_advisor._TRACE_DETAIL_MAX  # detail 截断
    assert trace['breakpoint'] == {'stage': 'mine', 'step_id': 's5', 'reason': '判定误报放弃'}


def test_extract_structured_advice_trace_invalid_type_and_stage():
    steps = [{'id': 's0', 'type': 'weird', 'title': 't'}, {'id': 's1', 'type': 'tool', 'stage': '乱写'}]
    out = fn_advisor.extract_structured_advice(_trace_payload(steps, {'stage': 'not-a-stage', 'reason': 'r'}))
    assert out['trace']['steps'][0]['type'] == 'text'  # 非法 type 归一
    assert out['trace']['steps'][1]['stage'] == '乱写'  # stage 保留原值（前端分组钳制）
    assert 'breakpoint' not in out['trace']  # 非法 stage → 整体丢弃


def test_extract_structured_advice_trace_steps_not_list():
    text = '```json\n{"summary": "m", "trace": {"steps": "oops"}}\n```'
    out = fn_advisor.extract_structured_advice(text)
    assert out is not None and 'trace' not in out  # steps 非法 → 不写 trace 键


def test_extract_structured_advice_legacy_no_trace():
    out = fn_advisor.extract_structured_advice('```json\n{"summary": "m"}\n```')
    assert out == {'summary': 'm'}


# ---- merge_agent_results（MCP staging + stdout 提取）----


def test_merge_staging_priority_and_backfill():
    agent_out = {
        'gt_id': 'G1',
        'status': 'ok',
        'advice': 'md',
        'ts': 100,
        'advice_structured': {
            'category': '其他',
            'summary': 'from-stdout',
            'suggestions': ['s1'],
            'trace': {
                'steps': [{
                    'id': 's0',
                    'type': 'tool',
                    'title': 't'
                }]
            }
        }
    }
    staging = {'category': '挖掘深度不足', 'summary': 'from-mcp', 'gt_id': 'G1', 'status': 'ok', 'source': 'mcp', 'ts': 200}
    merged = fn_advisor.merge_agent_results(agent_out, staging)
    assert merged['status'] == 'ok'
    assert merged['advice'] == 'md'  # 叙事恒取 agent_out
    assert merged['ts'] == 200
    assert merged['advice_structured']['category'] == '挖掘深度不足'  # staging 优先
    assert merged['advice_structured']['summary'] == 'from-mcp'
    assert merged['advice_structured']['suggestions'] == ['s1']  # stdout 回填缺失键
    assert 'trace' in merged['advice_structured']  # stdout 回填 trace
    assert 'source' not in merged['advice_structured']  # 元数据键剔除


def test_merge_staging_rescues_timeout():
    # agent 超时（error），但 MCP staging 已提交结论 → ok + 合成占位叙事
    agent_out = {
        'gt_id': 'G1',
        'status': 'error',
        'error': 'opencode timed out',
        'ts': 100,
        'advice': '[ERROR] opencode agent 失败: timeout'
    }
    staging = {'summary': 'm', 'reasoning': 'r', 'gt_id': 'G1', 'status': 'ok', 'source': 'mcp', 'ts': 90}
    merged = fn_advisor.merge_agent_results(agent_out, staging)
    assert merged['status'] == 'ok'
    assert 'm' in merged['advice'] and 'r' in merged['advice']
    assert 'timed out' in merged['advice']


def test_merge_both_fail():
    agent_out = {'gt_id': 'G1', 'status': 'error', 'error': 'boom', 'ts': 1}
    merged = fn_advisor.merge_agent_results(agent_out, None)
    assert merged['status'] == 'error'
    assert merged['error'] == 'boom'


def test_merge_no_staging_identity():
    agent_out = {
        'gt_id': 'G1',
        'status': 'ok',
        'advice': 'md',
        'ts': 5,
        'advice_structured': {
            'summary': 's'
        },
        'related_files': ['a.java']
    }
    merged = fn_advisor.merge_agent_results(agent_out, None)
    assert merged['status'] == 'ok'
    assert merged['advice'] == 'md'
    assert merged['advice_structured'] == {'summary': 's'}
    assert merged['related_files'] == ['a.java']
