"""fn_result_sink 单元测试：gt_id 清洗、JSON-RPC 分发、submit_result 原子写 staging。"""
import io
import json
import os

from evalscope.benchmarks.vuln_scan.analysis import fn_result_sink


def test_sanitize_gt_id():
    assert fn_result_sink.sanitize_gt_id('GT-001') == 'GT-001'
    assert fn_result_sink.sanitize_gt_id('gt/../../etc') == 'gt_.._.._etc'  # 路径字符替换
    assert fn_result_sink.sanitize_gt_id('') == 'unknown'
    assert fn_result_sink.sanitize_gt_id(None) == 'unknown'


def _sink(tmp_path):
    return fn_result_sink.FnResultSink(str(tmp_path), 'GT-001')


def test_handle_initialize_echoes_version():
    sink = _sink('/tmp/nonexistent-is-fine')  # initialize 不触盘
    resp = fn_result_sink.handle_message({
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'initialize',
        'params': {
            'protocolVersion': '2025-03-26'
        }
    }, sink)
    assert resp['id'] == 1
    assert resp['result']['protocolVersion'] == '2025-03-26'
    assert 'tools' in resp['result']['capabilities']
    # 不认识的版本 → 回最新
    resp2 = fn_result_sink.handle_message({
        'jsonrpc': '2.0',
        'id': 2,
        'method': 'initialize',
        'params': {
            'protocolVersion': '1999-01-01'
        }
    }, sink)
    assert resp2['result']['protocolVersion'] == fn_result_sink.SUPPORTED_PROTOCOL_VERSIONS[-1]


def test_handle_notification_and_ping():
    sink = _sink('/tmp/x')
    assert fn_result_sink.handle_message({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, sink) is None
    assert fn_result_sink.handle_message({
        'jsonrpc': '2.0',
        'id': 7,
        'method': 'ping'
    }, sink) == {
        'jsonrpc': '2.0',
        'id': 7,
        'result': {}
    }


def test_handle_tools_list():
    sink = _sink('/tmp/x')
    resp = fn_result_sink.handle_message({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/list'}, sink)
    names = [t['name'] for t in resp['result']['tools']]
    assert names == ['submit_result']


def test_handle_unknown_method_and_tool():
    sink = _sink('/tmp/x')
    resp = fn_result_sink.handle_message({'jsonrpc': '2.0', 'id': 4, 'method': 'resources/list'}, sink)
    assert resp['error']['code'] == -32601
    resp2 = fn_result_sink.handle_message({
        'jsonrpc': '2.0',
        'id': 5,
        'method': 'tools/call',
        'params': {
            'name': 'other_tool',
            'arguments': {}
        }
    }, sink)
    assert resp2['error']['code'] == -32602


def test_tools_call_submit_writes_staging(tmp_path):
    sink = _sink(tmp_path)
    payload = {
        'category': '挖掘深度不足',
        'summary': 'm',
        'trace': {
            'steps': [{
                'id': 's0',
                'type': 'dead_end',
                'title': 't'
            }]
        }
    }
    resp = fn_result_sink.handle_message({
        'jsonrpc': '2.0',
        'id': 9,
        'method': 'tools/call',
        'params': {
            'name': 'submit_result',
            'arguments': payload
        }
    }, sink)
    assert resp['result'].get('isError') is None
    path = os.path.join(str(tmp_path), '.mcp', 'GT-001.json')
    with open(path, encoding='utf-8') as f:
        entry = json.load(f)
    assert entry['gt_id'] == 'GT-001'
    assert entry['status'] == 'ok'
    assert entry['source'] == 'mcp'
    assert entry['ts'] > 0
    assert entry['trace']['steps'][0]['type'] == 'dead_end'
    # 无 .tmp 残留（原子写）
    assert not os.path.exists(path + '.tmp')


def test_tools_call_submit_invalid_payload(tmp_path):
    sink = _sink(tmp_path)
    # 空 payload / 非对象 → isError
    for args in ({}, 'not-a-dict'):
        resp = fn_result_sink.handle_message({
            'jsonrpc': '2.0',
            'id': 10,
            'method': 'tools/call',
            'params': {
                'name': 'submit_result',
                'arguments': args
            }
        }, sink)
        assert resp['result'].get('isError') is True


def test_submit_resubmit_overwrites(tmp_path):
    sink = _sink(tmp_path)
    sink.submit({'summary': 'v1'})
    sink.submit({'summary': 'v2'})
    with open(sink.staging_path, encoding='utf-8') as f:
        assert json.load(f)['summary'] == 'v2'


def test_serve_end_to_end(tmp_path):
    # stdio 行循环冒烟：initialize → initialized(notification) → tools/call → 输出校验
    sink = _sink(tmp_path)
    lines_in = '\n'.join([
        json.dumps({
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'initialize',
            'params': {
                'protocolVersion': '2025-06-18'
            }
        }),
        json.dumps({
            'jsonrpc': '2.0',
            'method': 'notifications/initialized'
        }),
        'not-json',
        json.dumps({
            'jsonrpc': '2.0',
            'id': 2,
            'method': 'tools/call',
            'params': {
                'name': 'submit_result',
                'arguments': {
                    'summary': 'ok'
                }
            }
        }),
    ]) + '\n'
    out = io.StringIO()
    fn_result_sink.serve(io.StringIO(lines_in), out, sink)
    responses = [json.loads(x) for x in out.getvalue().strip().splitlines()]
    assert len(responses) == 3  # initialize + parse error + tools/call；notification 无响应
    assert responses[0]['result']['protocolVersion'] == '2025-06-18'
    assert responses[1]['error']['code'] == -32700
    assert 'content' in responses[2]['result']
    assert os.path.exists(sink.staging_path)
