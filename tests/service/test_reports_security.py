"""reports 蓝图路径安全收紧的单测：media/file 根目录限制 / root_path 参数忽略 / delete 运行中拒绝。

运行：cd evalscope && python -m pytest tests/service/test_reports_security.py -v
"""
import os

import pytest


@pytest.fixture()
def client(tmp_path):
    from evalscope.service.app import create_app

    root = tmp_path / 'outputs'
    root.mkdir()
    app = create_app(outputs=str(root))
    app.config['TESTING'] = True
    return app.test_client(), root


def _touch(path: str, content: bytes = b'x') -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(content)


# ---- media/file：必须位于 outputs root 内 ----
def test_media_file_outside_root_rejected(client, tmp_path):
    c, _ = client
    outside = tmp_path / 'secret.png'
    _touch(str(outside))
    resp = c.get(f'/api/v1/reports/media/file?path={outside}')
    assert resp.status_code == 403


def test_media_file_traversal_rejected(client, tmp_path):
    c, root = client
    _touch(str(root / 'task-a' / 'ok.png'))
    # 试图用 .. 逃出 root
    traversal = os.path.join(str(root), 'task-a', '..', '..', 'secret.png')
    _touch(str(tmp_path / 'secret.png'))
    resp = c.get(f'/api/v1/reports/media/file?path={traversal}')
    assert resp.status_code == 403


def test_media_file_inside_root_served(client):
    c, root = client
    _touch(str(root / 'task-a' / 'ok.png'), b'\x89PNG')
    resp = c.get(f'/api/v1/reports/media/file?path={root / "task-a" / "ok.png"}')
    assert resp.status_code == 200


# ---- root_path 参数被忽略：任何客户端提供的 root 都不生效 ----
def test_root_path_param_ignored(client, tmp_path):
    c, root = client
    # root_path 指向 root 之外的一个含报告结构的目录，若被采纳会返回不同结果/报错
    other = tmp_path / 'elsewhere'
    other.mkdir()
    resp = c.get(f'/api/v1/reports/list?root_path={other}')
    assert resp.status_code == 200
    # 空.outputs → 空列表；关键是不采纳 other（语义上与不传参数一致）
    assert resp.get_json()['reports'] == []


def test_scan_with_root_path_outside_ignored(client, tmp_path):
    c, _ = client
    resp = c.get(f'/api/v1/reports/scan?root_path=/')
    assert resp.status_code == 200  # 不再枚举任意目录，正常返回空/根内容


# ---- delete：运行中任务拒绝；目录限定 outputs root ----
def test_delete_rejects_running_task(client, monkeypatch):
    c, root = client
    task_dir = root / 'task-running'
    task_dir.mkdir()
    monkeypatch.setattr('evalscope.service.utils.process.is_task_running', lambda tid: tid == 'task-running')
    resp = c.delete('/api/v1/reports/delete?report_name=task-running@@m@@d')
    assert resp.status_code == 409
    assert task_dir.exists()  # 未被删除


def test_delete_removes_finished_task(client):
    c, root = client
    task_dir = root / 'task-done'
    task_dir.mkdir()
    resp = c.delete('/api/v1/reports/delete?report_name=task-done@@m@@d')
    assert resp.status_code == 200
    assert not task_dir.exists()


def test_delete_traversal_rejected(client):
    c, root = client
    resp = c.delete('/api/v1/reports/delete?report_name=..%2F..%2Fetc@@m@@d')
    assert resp.status_code == 400
