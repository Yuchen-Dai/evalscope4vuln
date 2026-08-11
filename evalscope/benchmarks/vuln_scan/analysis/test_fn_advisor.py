"""fn_advisor 单元测试：FN 提取、相关文件、session 摘要过滤。"""
from evalscope.benchmarks.vuln_scan.analysis import fn_advisor


def test_extract_fn_schema2():
    vm = {
        'schema': 2,
        'gt': [
            {'gt_id': 'GT-001', 'vuln_type': 'sql-injection',
             'location': {'file': 'a/UserController.java', 'line': 10}},
            {'gt_id': 'GT-002', 'vuln_type': 'xss',
             'location': {'file': 'b/XssView.java', 'line': 5}},
        ],
        'type': {'missed_gt': ['GT-001']},   # GT-001 漏报
        'loc': {'missed_gt': ['GT-001']},
    }
    assert [g['gt_id'] for g in fn_advisor.extract_fn(vm)] == ['GT-001']


def test_extract_fn_schema1():
    vm = {'schema': 1, 'gt': [{'gt_id': 'G1', 'location': {'file': 'x.java'}}],
          'missed_gt': ['G1']}
    assert [g['gt_id'] for g in fn_advisor.extract_fn(vm)] == ['G1']


def test_extract_fn_empty():
    assert fn_advisor.extract_fn({}) == []
    assert fn_advisor.extract_fn({'gt': [], 'type': {'missed_gt': []}}) == []


def test_relevant_files_source_sink():
    fn = {'location': {'file': 'a/Mid.java'},
          'source': {'file': 'a/Source.java', 'line': 1},
          'sink': {'file': 'a/Sink.java', 'line': 9}}
    assert fn_advisor.relevant_files(fn) == ['a/Source.java', 'a/Sink.java']


def test_relevant_files_fallback_location():
    fn = {'location': {'file': 'a/Mid.java', 'line': 3}}
    assert fn_advisor.relevant_files(fn) == ['a/Mid.java']


def test_summarize_sessions_hit():
    sessions = [
        {'task_id': 't1', 'prompt': '', 'session': {'parts': [
            {'type': 'text', 'text': '读取 a/Source.java 发现 SQL 拼接'},
            {'type': 'reasoning', 'text': '分析数据流'},
        ]}},
        {'task_id': 't2', 'prompt': '', 'session': {'parts': [
            {'type': 'text', 'text': '无关内容 elsewhere'},
        ]}},
    ]
    summary, hit = fn_advisor.summarize_sessions(sessions, ['a/Source.java'])
    assert 't1' in hit
    assert 't2' not in hit
    assert 'Source.java' in summary


def test_summarize_sessions_no_files():
    assert fn_advisor.summarize_sessions([{'session': {'parts': []}}], []) == ('', [])


def test_summarize_sessions_basename_match():
    # GT 给全路径，session 只提 basename 也应命中
    sessions = [{'task_id': 't9', 'prompt': '', 'session': {'parts': [
        {'type': 'text', 'text': '查看 Sink.java'},
    ]}}]
    _, hit = fn_advisor.summarize_sessions(sessions, ['com/x/a/Sink.java'])
    assert 't9' in hit
