"""FN 漏报分析异步任务运行器（线程版）。

fn-advice 是纯 IO（httpx 拉图灵 sessions + 子进程 opencode agent），用**线程**而非
spawn 子进程（无模型加载/GPU，spawn 秒级启动不划算）。

- 注册表 `_active_fn_tasks: task_id -> (thread, stop_event)`，加锁（仿 process.py）。
- worker（daemon thread）串行遍历 fn_list，复用单个 TuringClient；全量 sessions 与索引
  一次性落盘共享 workdir，每完成一个 gt_id 增量写结果缓存（reports._save_fn_advice）
  + 更新 progress 文件。
- agent 结论经 MCP submit_result 写 `<fn_advice>/.mcp/` staging（真实输出目录，服务
  重启仍可读）；analyze_one 内部与 stdout 提取结果合并，超时/异常不丢已提交结论。
- progress 文件 `<outputs_root>/<prefix>/fn_advice/<dataset>.progress.json`（独立，
  不复用 <work_dir>/progress.json，避免被 /eval/tasks 当 eval 任务误扫）。
- 完成/停止/异常都写终态 progress；worker finally unregister。

复用：reports._save_fn_advice（延迟 import 避免循环）、fn_advisor.analyze_one /
build_sessions_index / merge_agent_results、TuringClient。
"""
import asyncio
import json
import os
import tempfile
import threading
import time
from datetime import datetime

from evalscope.benchmarks.vuln_scan import config as vb_config
from evalscope.benchmarks.vuln_scan.analysis import fn_advisor
from evalscope.benchmarks.vuln_scan.turing.client import TuringClient
from evalscope.utils.logger import get_logger

logger = get_logger()

# task_id -> (thread, stop_event)
_active_fn_tasks: dict = {}
_active_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now().isoformat(timespec='seconds')


# ---- progress 文件（原子 tmp+replace 写）----


def _progress_path(root: str, prefix: str, dataset: str) -> str:
    return os.path.join(root, prefix, 'fn_advice', f'{dataset}.progress.json')


def _read_fn_progress(root: str, prefix: str, dataset: str) -> dict:
    path = _progress_path(root, prefix, dataset)
    if not os.path.exists(path):
        return {
            'status': 'idle',
            'pipeline': 'fn_advice',
            'dataset': dataset,
            'total_count': 0,
            'processed_count': 0,
            'percent': 0.0,
            'updated_at': ''
        }
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f) or {}
    except (json.JSONDecodeError, OSError):
        return {'status': 'idle', 'percent': 0.0}


def _write_fn_progress(root: str, prefix: str, dataset: str, **fields) -> None:
    """读-改-写 + 原子替换（仿 progress_tracker.py）。"""
    path = _progress_path(root, prefix, dataset)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = _read_fn_progress(root, prefix, dataset)
    data.update(fields)
    data['pipeline'] = 'fn_advice'
    data['dataset'] = dataset
    data['updated_at'] = _now_iso()
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ---- 注册表 ----


def register(task_id: str, thread: threading.Thread, stop_event: threading.Event) -> None:
    with _active_lock:
        _active_fn_tasks[task_id] = (thread, stop_event)


def unregister(task_id: str) -> None:
    with _active_lock:
        _active_fn_tasks.pop(task_id, None)


def is_fn_task_running(task_id: str) -> bool:
    with _active_lock:
        entry = _active_fn_tasks.get(task_id)
    return entry is not None and entry[0].is_alive()


def is_fn_task_running_by_prefix(root: str, prefix: str, dataset: str) -> bool:
    """按 report+dataset 维度判 running：progress 文件 status=running 且对应线程还活。"""
    p = _read_fn_progress(root, prefix, dataset)
    if p.get('status') != 'running':
        return False
    tid = p.get('task_id')
    if not tid:
        return False
    return is_fn_task_running(tid)


def stop_fn_task(task_id: str) -> bool:
    with _active_lock:
        entry = _active_fn_tasks.get(task_id)
    if entry is None:
        return False
    entry[1].set()  # stop_event：worker 下个 gt_id 边界退出
    logger.info(f'[fn_advice] task {task_id} stop requested')
    return True


def list_active_fn_tasks():
    with _active_lock:
        return list(_active_fn_tasks.items())


# ---- worker ----


def _prepare_repo(source_path: str, repo_dir: str) -> bool:
    """把被测源码落到 workdir/repo：zip 解压 / 目录 copytree / 缺失则跳过（agent 仅用 sessions）。

    返回是否成功准备了源码。
    """
    if not source_path or not os.path.exists(source_path):
        logger.warning(f'[fn_advice] source_path 缺失或不存在: {source_path!r} → agent 仅用 sessions（无源码）')
        return False
    os.makedirs(repo_dir, exist_ok=True)
    if source_path.lower().endswith('.zip'):
        import zipfile
        try:
            with zipfile.ZipFile(source_path) as z:
                z.extractall(repo_dir)
            return True
        except Exception as e:
            logger.warning(f'[fn_advice] 解压源码失败 {source_path!r}: {e}')
            return False
    if os.path.isdir(source_path):
        import shutil
        shutil.copytree(source_path, repo_dir, dirs_exist_ok=True)
        return True
    logger.warning(f'[fn_advice] source_path 非 zip/目录: {source_path!r} → 跳过')
    return False


def _dump_sessions(workdir: str, sessions: list) -> None:
    """全量 sessions + 索引一次性落盘（全任务共享，agent 按 task_id 分窗读）。

    sessions.json 用 indent=1 多行 pretty：``grep -n`` 取行号 + ``sed -n 'X,Yp'`` 分窗
    阅读单个 session 的 parts；sessions_index.jsonl 每行一个 session 摘要（先 grep 它定位）。
    """
    with open(os.path.join(workdir, 'sessions.json'), 'w', encoding='utf-8') as f:
        json.dump(sessions, f, ensure_ascii=False, indent=1)
    with open(os.path.join(workdir, 'sessions_index.jsonl'), 'w', encoding='utf-8') as f:
        for entry in fn_advisor.build_sessions_index(sessions):
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def _fn_worker(task_id, root, prefix, dataset, fn_list, pid, jid, judge_cfg, source_path, turing_base_url, stop_event):
    """daemon thread 入口：建共享 workdir（源码+全量 sessions+索引）→ 串行 opencode 分析循环。"""
    import shutil

    # 延迟 import：reports.py 顶部会 import 本模块（start_fn_task 等），避免循环
    from evalscope.service.blueprints.reports import _save_fn_advice

    async def _run():
        client = TuringClient(base_url=turing_base_url)
        workdir = tempfile.mkdtemp(prefix='fnadvice-')
        try:
            await client.login(vb_config.TURING_USERNAME, vb_config.TURING_PASSWORD)
            # 拉全量 sessions 一次性落盘（全量 + 索引），agent 先 grep 索引再分窗读全量文件
            all_sessions = ((await client.get_job_sessions(pid, jid)) or {}).get('sessions') or []
            _prepare_repo(source_path, os.path.join(workdir, 'repo'))
            _dump_sessions(workdir, all_sessions)

            # MCP staging 落真实输出目录（非临时 workdir）：服务重启 / 手动跑 opencode 均可读
            sink_dir = os.path.join(root, prefix, 'fn_advice')
            total = len(fn_list)
            processed = 0
            errors: list = []
            _write_fn_progress(
                root,
                prefix,
                dataset,
                status='running',
                task_id=task_id,
                total_count=total,
                processed_count=0,
                percent=0.0,
                errors=errors,
                current_gt_id=None
            )
            for idx, fn in enumerate(fn_list):
                if stop_event.is_set():
                    _write_fn_progress(
                        root,
                        prefix,
                        dataset,
                        status='stopped',
                        processed_count=processed,
                        percent=(processed / total * 100 if total else 100),
                        current_gt_id=None
                    )
                    logger.info(f'[fn_advice] task {task_id} 已停止（已完成 {processed}/{total}）')
                    return
                gt_id = fn.get('gt_id')
                sink = {'dir': sink_dir, 'gt_id': gt_id}
                _write_fn_progress(root, prefix, dataset, current_gt_id=gt_id)
                try:
                    r = await fn_advisor.analyze_one(fn, workdir, judge_cfg, idx, sink=sink)
                except Exception as e:
                    logger.error(f'[fn_advice] gt_id={gt_id} 分析异常: {e}', exc_info=True)
                    # MCP staging 兜底：agent 异常/超时前已 submit 的结论不丢
                    r = fn_advisor.merge_agent_results({
                        'gt_id': gt_id,
                        'status': 'error',
                        'error': str(e),
                        'ts': int(time.time()),
                        'related_files': fn_advisor.relevant_files(fn)
                    }, fn_advisor.read_staging(sink))
                _save_fn_advice(root, prefix, dataset, r)
                processed += 1
                if r.get('status') == 'error':
                    errors.append(gt_id)
                _write_fn_progress(
                    root,
                    prefix,
                    dataset,
                    processed_count=processed,
                    percent=(processed / total * 100 if total else 100),
                    errors=errors,
                    current_gt_id=None
                )
            _write_fn_progress(root, prefix, dataset, status='completed', percent=100.0, current_gt_id=None)
            logger.info(f'[fn_advice] task {task_id} 完成: {processed}/{total} (errors={len(errors)})')
        finally:
            await client.aclose()
            shutil.rmtree(workdir, ignore_errors=True)

    try:
        asyncio.run(_run())
    except Exception as e:
        logger.error(f'[fn_advice] task {task_id} 失败: {e}', exc_info=True)
        _write_fn_progress(root, prefix, dataset, status='error', error=str(e))
    finally:
        unregister(task_id)


def start_fn_task(task_id, root, prefix, dataset, fn_list, pid, jid, judge_cfg, source_path, turing_base_url) -> None:
    """起 daemon thread 跑 fn-advice 全量分析，立即返回（不阻塞调用方）。"""
    stop_event = threading.Event()
    t = threading.Thread(
        target=_fn_worker,
        args=(task_id, root, prefix, dataset, fn_list, pid, jid, judge_cfg, source_path, turing_base_url, stop_event),
        daemon=True,
        name=f'fn-advice-{task_id}',
    )
    register(task_id, t, stop_event)
    t.start()
    logger.info(f'[fn_advice] task {task_id} 启动: {len(fn_list)} 个漏报, project={pid} job={jid}')
