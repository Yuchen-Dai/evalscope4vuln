"""任务对账链路单测：task_runtime 读写 / pid 存活 / progress 补丁 / reconcile / invoke 服务端 task_id。

运行：cd evalscope && python -m pytest tests/service/test_task_reconcile.py -v
"""
import json
import os

import pytest

from evalscope.service.utils.task_runtime import (
    is_process_alive,
    patch_progress,
    proc_start_ticks,
    read_runtime,
    write_runtime,
)


def _write_json(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f)


# ---- task_runtime 读写 ----
def test_runtime_roundtrip(tmp_path):
    work_dir = str(tmp_path / 'task-a')
    write_runtime(work_dir, pid=123, start_ticks=456)
    runtime = read_runtime(work_dir)
    assert runtime == {'pid': 123, 'start_ticks': 456}
    assert read_runtime(str(tmp_path / 'missing')) is None


# ---- /proc 存活判定 ----
def test_proc_start_ticks_self():
    ticks = proc_start_ticks(os.getpid())
    assert ticks is not None and ticks > 0


def test_proc_start_ticks_dead_pid():
    # pid 空间顶端的值几乎不可能存在
    assert proc_start_ticks(2**22) is None


def test_is_process_alive_variants():
    assert is_process_alive(os.getpid(), proc_start_ticks(os.getpid())) is True
    # start_ticks 不匹配 → pid 已被复用，视为死
    assert is_process_alive(os.getpid(), proc_start_ticks(os.getpid()) + 1) is False
    assert is_process_alive(2**22, None) is False
    # start_ticks 未知（非 Linux 兜底路径）→ 退化为存在性探测
    assert is_process_alive(os.getpid(), None) is True


# ---- patch_progress ----
def test_patch_progress_preserves_fields(tmp_path):
    work_dir = str(tmp_path)
    _write_json(os.path.join(work_dir, 'progress.json'),
                {'status': 'running', 'percent': 37.0, 'updated_at': '2026-08-20T10:00:00'})
    assert patch_progress(work_dir, 'stopped', 'Stopped by user') is True
    with open(os.path.join(work_dir, 'progress.json'), encoding='utf-8') as f:
        state = json.load(f)
    assert state['status'] == 'stopped'
    assert state['error'] == 'Stopped by user'
    assert state['percent'] == 37.0
    assert state['updated_at'] == '2026-08-20T10:00:00'


def test_patch_progress_missing_file(tmp_path):
    assert patch_progress(str(tmp_path / 'none'), 'error', 'x') is False


# ---- reconcile_running_task ----
def test_reconcile_marks_error_when_child_dead(tmp_path, monkeypatch):
    from evalscope.service.blueprints import eval as eval_bp
    from evalscope.service.utils.process import is_task_running

    work_dir = str(tmp_path / 'task-zombie')
    _write_json(os.path.join(work_dir, 'progress.json'), {'status': 'running', 'percent': 0.0})
    write_runtime(work_dir, pid=2**22, start_ticks=1)

    status = eval_bp.reconcile_running_task('task-zombie', work_dir)
    assert status == 'error'
    with open(os.path.join(work_dir, 'progress.json'), encoding='utf-8') as f:
        assert json.load(f)['status'] == 'error'
    assert not is_task_running('task-zombie')


def test_reconcile_adopts_alive_orphan(tmp_path, monkeypatch):
    from evalscope.service.blueprints import eval as eval_bp
    from evalscope.service.utils.process import is_task_running, unregister_process

    work_dir = str(tmp_path / 'task-orphan')
    _write_json(os.path.join(work_dir, 'progress.json'), {'status': 'running', 'percent': 10.0})
    write_runtime(work_dir, pid=4242, start_ticks=999)

    monkeypatch.setattr(eval_bp, 'is_process_alive', lambda pid, ticks: True)
    # process.py 内部是函数级 from-import，需一并 patch 源头模块
    monkeypatch.setattr('evalscope.service.utils.task_runtime.is_process_alive', lambda pid, ticks: True)
    assert eval_bp.reconcile_running_task('task-orphan', work_dir) == 'running'
    assert is_task_running('task-orphan')  # adopted（monkeypatch 不影响 process.py 内的探测）
    with open(os.path.join(work_dir, 'progress.json'), encoding='utf-8') as f:
        assert json.load(f)['status'] == 'running'  # 未误写终态
    unregister_process('task-orphan')


def test_reconcile_stale_tasks_sweep(tmp_path):
    from evalscope.service.blueprints.eval import reconcile_stale_tasks

    running_dir = tmp_path / 'task-r'
    done_dir = tmp_path / 'task-d'
    _write_json(str(running_dir / 'progress.json'), {'status': 'running', 'percent': 0.0})
    write_runtime(str(running_dir), pid=2**22, start_ticks=1)
    _write_json(str(done_dir / 'progress.json'), {'status': 'completed', 'percent': 100.0})

    assert reconcile_stale_tasks(str(tmp_path)) == 1
    with open(running_dir / 'progress.json', encoding='utf-8') as f:
        assert json.load(f)['status'] == 'error'
    with open(done_dir / 'progress.json', encoding='utf-8') as f:
        assert json.load(f)['status'] == 'completed'  # 终态不动


# ---- invoke：服务端生成 task_id + 复用 409 ----
class _FakeProc:

    def __init__(self):
        self.pid = os.getpid()


@pytest.fixture()
def flask_client(tmp_path, monkeypatch):
    from evalscope.service.app import create_app

    monkeypatch.setattr('evalscope.service.blueprints.eval.start_subprocess', lambda *a, **k: _FakeProc())
    app = create_app(outputs=str(tmp_path))
    app.config['TESTING'] = True
    return app.test_client(), str(tmp_path)


def test_invoke_generates_server_side_task_id(flask_client):
    client, root = flask_client
    resp = client.post('/api/v1/eval/invoke', json={'datasets': ['vuln_flowise'], 'scan_config': {}})
    assert resp.status_code == 202
    task_id = resp.get_json()['task_id']
    assert task_id.startswith('task-')
    assert os.path.exists(os.path.join(root, task_id, 'task_runtime.json'))
    assert os.path.exists(os.path.join(root, task_id, 'scan_config.json'))


def test_invoke_rejects_existing_work_dir(flask_client):
    client, root = flask_client
    existing = os.path.join(root, 'eval_legacy')
    os.makedirs(existing)
    resp = client.post(
        '/api/v1/eval/invoke',
        json={'datasets': ['vuln_flowise'], 'scan_config': {}},
        headers={'EvalScope-Task-Id': 'eval_legacy'},
    )
    assert resp.status_code == 409


def test_resume_still_requires_task_id_header(flask_client):
    client, _ = flask_client
    resp = client.post('/api/v1/eval/resume/invoke', json={'datasets': ['vuln_flowise'], 'scan_config': {}})
    assert resp.status_code == 400


# ---- ProgressTracker error 摘要 ----
def test_progress_tracker_writes_error_summary(tmp_path):
    from evalscope.utils.tqdm_utils.progress_tracker import ProgressTracker

    with pytest.raises(RuntimeError):
        with ProgressTracker(work_dir=str(tmp_path), pipeline='eval', total_count=1):
            raise RuntimeError('boom')
    with open(tmp_path / 'progress.json', encoding='utf-8') as f:
        state = json.load(f)
    assert state['status'] == 'error'
    assert 'RuntimeError' in state['error'] and 'boom' in state['error']

    tracker = ProgressTracker(work_dir=str(tmp_path), pipeline='eval', total_count=1)
    tracker.__enter__()
    tracker.__exit__(None, None, None)
    with open(tmp_path / 'progress.json', encoding='utf-8') as f:
        state = json.load(f)
    assert state['status'] == 'completed'
    assert state['error'] is None
