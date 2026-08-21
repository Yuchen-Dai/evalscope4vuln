"""offline 单元测试：sessions 导出提取（有效判定/拒收/去重/validation 合并）+ parse_findings 契约。"""
import json
import pytest

from evalscope.benchmarks.vuln_scan.turing import offline
from evalscope.benchmarks.vuln_scan.turing.client import parse_findings

FINDING_DATA = {
    'vuln_type': 'SSRF',
    'severity': 'HIGH',
    'title': 'fetch-links SSRF',
    'source': {
        'file': 'pkg/a.ts',
        'line': 1
    },
    'sink': {
        'file': 'pkg/b.ts',
        'line': 9
    },
    'call_chain': [{
        'file': 'pkg/a.ts',
        'line': 1
    }, {
        'file': 'pkg/c.ts',
        'line': 5
    }],
}


def _submit(artifact_type, data, output, task_id='t-1', tool='blackboard_submit_artifact'):
    return {
        'type': 'tool',
        'tool': tool,
        'input': {
            'task_id': task_id,
            'artifact_type': artifact_type,
            'data': data
        },
        'output': output
    }


def _sess(parts, task_id='t-1', model='m1'):
    return {
        'task_id': task_id,
        'session_id': 'ses-1',
        'task_type': 'mining',
        'session': {
            'info': {
                'modelID': model
            },
            'parts': parts
        }
    }


def _ok(artifact_id='art-1', display_id='F-001'):
    return {'artifact_id': artifact_id, 'display_id': display_id, 'downstream_task_ids': []}


def test_extract_dict_data_ok():
    """glm/kimi 形态：data 为 dict、output 带 artifact_id → 入库。"""
    parts = [
        _submit('detection', {'file': 'a.ts'}, _ok('d-1', 'D-001')),
        _submit('finding', FINDING_DATA, _ok()),
    ]
    rep = offline.extract_report_from_sessions({'sessions': [_sess(parts)]})
    assert len(rep.findings) == 1
    f = rep.findings[0]
    assert f['id'] == 'art-1'
    assert f['display_id'] == 'F-001'
    assert f['task_id'] == 't-1'
    assert f['vuln_type'] == 'SSRF'
    st = rep.stats
    assert st['findings'] == 1 and st['detections'] == 1
    assert st['findings_rejected'] == 0 and st['model_ids'] == ['m1']


def test_extract_str_data_rejected():
    """minimax 形态：data 为 JSON 字符串、output 为校验错误字符串 → 拒收。"""
    parts = [
        _submit(
            'finding', json.dumps(FINDING_DATA), '1 validation error for call[submit_artifact]\n'
            'data\n  Input should be a valid dictionary'
        )
    ]
    rep = offline.extract_report_from_sessions({'sessions': [_sess(parts)]})
    assert rep.findings == []
    assert rep.stats['findings_rejected'] == 1
    assert rep.stats['reject_samples']


def test_empty_artifact_id_rejected():
    """output 是 dict 但 artifact_id 为空串 → 拒收（关键边界）。"""
    parts = [_submit('finding', FINDING_DATA, {'artifact_id': '', 'display_id': '', 'downstream_task_ids': []})]
    rep = offline.extract_report_from_sessions({'sessions': [_sess(parts)]})
    assert rep.findings == []
    assert rep.stats['findings_rejected'] == 1


def test_detection_id_display_rejected():
    """output 为 'Error: detection_id must be a UUID...' → 拒收。"""
    parts = [
        _submit(
            'finding', {
                **FINDING_DATA, 'detection_id': 'D-553'
            }, "Error: detection_id must be a UUID, got display_id 'D-553'"
        )
    ]
    rep = offline.extract_report_from_sessions({'sessions': [_sess(parts)]})
    assert rep.findings == []
    assert rep.stats['findings_rejected'] == 1


def test_validation_result_merged():
    """validation 提交成功且带 finding_id → 合并回 finding.validation_result。"""
    parts = [
        _submit('finding', FINDING_DATA, _ok('f-1')),
        _submit('validation', {
            'finding_id': 'f-1',
            'validation_result': 'CONFIRMED'
        }, _ok('v-1')),
        _submit(
            'validation', {
                'finding_id': 'no-such',
                'validation_result': 'LIKELY'
            }, '2 validation errors for call[submit_artifact]'
        ),
    ]
    rep = offline.extract_report_from_sessions({'sessions': [_sess(parts)]})
    assert rep.findings[0]['validation_result'] == 'CONFIRMED'
    assert rep.stats['validations'] == 1 and rep.stats['validations_rejected'] == 1


def test_already_scheduled_kept():
    """output 含 artifact_id 且 already_scheduled=True → 仍视为入库。"""
    out = {**_ok('f-9'), 'already_scheduled': True}
    rep = offline.extract_report_from_sessions({'sessions': [_sess([_submit('finding', FINDING_DATA, out)])]})
    assert len(rep.findings) == 1


def test_duplicate_artifact_dedup():
    """同 artifact_id 重复提交 → 只保留一条。"""
    parts = [_submit('finding', FINDING_DATA, _ok('dup')), _submit('finding', FINDING_DATA, _ok('dup'))]
    rep = offline.extract_report_from_sessions({'sessions': [_sess(parts)]})
    assert len(rep.findings) == 1
    assert rep.stats['duplicates'] == 1


def test_non_submit_tool_ignored():
    """非 submit 类 tool 调用不参与统计。"""
    parts = [{
        'type': 'tool',
        'tool': 'read',
        'input': {
            'path': 'a.ts'
        },
        'output': 'ok'
    },
             _submit('finding', FINDING_DATA, _ok())]
    rep = offline.extract_report_from_sessions({'sessions': [_sess(parts)]})
    assert rep.stats['findings'] == 1


def test_empty_sessions_ok():
    rep = offline.extract_report_from_sessions({'sessions': []})
    assert rep.findings == [] and rep.stats['sessions'] == 0


def test_missing_sessions_key_raises():
    with pytest.raises(ValueError):
        offline.extract_report_from_sessions({'foo': 1})
    with pytest.raises(ValueError):
        offline.extract_report_from_sessions([1, 2])


def test_load_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        offline.load_sessions_report(str(tmp_path / 'nope.json'))


def test_load_bad_json_raises(tmp_path):
    p = tmp_path / 'bad.json'
    p.write_text('not json', encoding='utf-8')
    with pytest.raises(ValueError):
        offline.load_sessions_report(str(p))


def test_parse_findings_compat():
    """提取结果与 parse_findings 契约对齐：locations 从 source/sink/call_chain 提取、类型归一、id 生效。"""
    parts = [_submit('finding', FINDING_DATA, _ok('af-1', 'F-101'))]
    rep = offline.extract_report_from_sessions({'sessions': [_sess(parts)]})
    findings = parse_findings(rep.findings)
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_id == 'af-1'
    assert f.vuln_type_norm == 'ssrf'
    assert {(loc.file, loc.line) for loc in f.locations} == {('pkg/a.ts', 1), ('pkg/b.ts', 9), ('pkg/c.ts', 5)}


def test_dirty_line_normalized():
    """脏行号（'167, 212' 范围串/非数字）→ 首个可解析整数或 None，不炸 parse_findings。"""
    data = {
        **FINDING_DATA,
        'source': {
            'file': 'pkg/a.ts',
            'line': '167, 212'
        },
        'sink': {
            'file': 'pkg/b.ts',
            'line': 'x?'
        },
        'call_chain': [{
            'file': 'pkg/c.ts',
            'line': '8'
        }],
    }
    rep = offline.extract_report_from_sessions({'sessions': [_sess([_submit('finding', data, _ok())])]})
    findings = parse_findings(rep.findings)
    assert {(loc.file, loc.line) for loc in findings[0].locations} == \
        {('pkg/a.ts', 167), ('pkg/b.ts', None), ('pkg/c.ts', 8)}


def test_context_ids_extracted():
    """knowledge 载荷回显 job_id/project_id（python repr 形态）→ 提取进 stats。"""
    JID, PID = '0bce5ab3-92e7-4692-9407-86bb74eac98d', '557e66c6-e91a-4eb9-97a2-582796e54d85'
    parts = [
        _submit('finding', FINDING_DATA, _ok()),
        {
            'type': 'tool',
            'tool': 'knowledge_knowledge_query',
            'input': {
                'query': 'ssrf'
            },
            'output': f"[{{'id': 63, 'job_id': '{JID}', 'project_id': '{PID}', 'knowledge_type': 'fp_pattern'}}]"
        },
        {
            'type': 'tool',
            'tool': 'knowledge_knowledge_publish',
            'input': {
                'job_id': JID,
                'project_id': PID,
                'content': {}
            },
            'output': 'ok'
        },
    ]
    rep = offline.extract_report_from_sessions({'sessions': [_sess(parts)]})
    assert rep.stats['project_id'] == PID
    assert rep.stats['job_id'] == JID


def test_context_ids_absent():
    """无 id 载荷（如 minimax 无 knowledge 调用）→ 空串，不影响提取。"""
    rep = offline.extract_report_from_sessions({'sessions': [_sess([_submit('finding', FINDING_DATA, _ok())])]})
    assert rep.stats['project_id'] == ''
    assert rep.stats['job_id'] == ''
