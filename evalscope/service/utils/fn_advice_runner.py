"""FN 漏报分析异步任务运行器（线程版）。

fn-advice 是纯 IO（httpx 拉图灵 sessions + 同步 LLM judge），用**线程**而非 spawn
子进程（无模型加载/GPU，spawn 秒级启动不划算）。

- 注册表 `_active_fn_tasks: task_id -> (thread, stop_event)`，加锁（仿 process.py）。
- worker（daemon thread）串行遍历 fn_list，**复用单个 TuringClient + LLMJudge**，
  每完成一个 gt_id 增量写结果缓存（reports._save_fn_advice）+ 更新 progress 文件。
- progress 文件 `<outputs_root>/<prefix>/fn_advice/<dataset>.progress.json`（独立，
  不复用 <work_dir>/progress.json，避免被 /eval/tasks 当 eval 任务误扫）。
- 完成/停止/异常都写终态 progress；worker finally unregister。

复用：reports._build_judge / reports._save_fn_advice（延迟 import 避免循环）、
fn_advisor.analyze_one / relevant_files、TuringClient。
"""
import asyncio
import json
import os
import threading
from datetime import datetime

from evalscope.utils.logger import get_logger

from evalscope.benchmarks.vuln_scan import config as vb_config
from evalscope.benchmarks.vuln_scan.analysis import fn_advisor
from evalscope.benchmarks.vuln_scan.turing.client import TuringClient

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
        return {'status': 'idle', 'pipeline': 'fn_advice', 'dataset': dataset,
                'total_count': 0, 'processed_count': 0, 'percent': 0.0, 'updated_at': ''}
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

def _fn_worker(task_id, root, prefix, dataset, fn_list, pid, jid, judge_cfg, turing_base_url, stop_event):
    """daemon thread 入口：asyncio.run 跑串行分析循环。"""
    # 延迟 import：reports.py 顶部会 import 本模块（start_fn_task 等），避免循环
    from evalscope.service.blueprints.reports import _build_judge, _save_fn_advice

    async def _run():
        client = TuringClient(base_url=turing_base_url)
        try:
            await client.login(vb_config.TURING_USERNAME, vb_config.TURING_PASSWORD)
            judge = _build_judge(judge_cfg)
            total = len(fn_list)
            processed = 0
            errors: list = []
            _write_fn_progress(root, prefix, dataset, status='running', task_id=task_id,
                               total_count=total, processed_count=0, percent=0.0,
                               errors=errors, current_gt_id=None)
            for fn in fn_list:
                if stop_event.is_set():
                    _write_fn_progress(root, prefix, dataset, status='stopped', processed_count=processed,
                                       percent=(processed / total * 100 if total else 100),
                                       current_gt_id=None)
                    logger.info(f'[fn_advice] task {task_id} 已停止（已完成 {processed}/{total}）')
                    return
                gt_id = fn.get('gt_id')
                _write_fn_progress(root, prefix, dataset, current_gt_id=gt_id)
                try:
                    r = await fn_advisor.analyze_one(fn, pid, jid, client, judge)
                except Exception as e:
                    logger.error(f'[fn_advice] gt_id={gt_id} 分析异常: {e}', exc_info=True)
                    r = {'gt_id': gt_id, 'status': 'error', 'error': str(e),
                         'related_files': fn_advisor.relevant_files(fn)}
                _save_fn_advice(root, prefix, dataset, r)
                processed += 1
                if r.get('status') == 'error':
                    errors.append(gt_id)
                _write_fn_progress(root, prefix, dataset, processed_count=processed,
                                   percent=(processed / total * 100 if total else 100),
                                   errors=errors, current_gt_id=None)
            _write_fn_progress(root, prefix, dataset, status='completed', percent=100.0, current_gt_id=None)
            logger.info(f'[fn_advice] task {task_id} 完成: {processed}/{total} (errors={len(errors)})')
        finally:
            await client.aclose()

    try:
        asyncio.run(_run())
    except Exception as e:
        logger.error(f'[fn_advice] task {task_id} 失败: {e}', exc_info=True)
        _write_fn_progress(root, prefix, dataset, status='error', error=str(e))
    finally:
        unregister(task_id)


def start_fn_task(task_id, root, prefix, dataset, fn_list, pid, jid, judge_cfg, turing_base_url) -> None:
    """起 daemon thread 跑 fn-advice 全量分析，立即返回（不阻塞调用方）。"""
    stop_event = threading.Event()
    t = threading.Thread(
        target=_fn_worker,
        args=(task_id, root, prefix, dataset, fn_list, pid, jid, judge_cfg, turing_base_url, stop_event),
        daemon=True, name=f'fn-advice-{task_id}',
    )
    register(task_id, t, stop_event)
    t.start()
    logger.info(f'[fn_advice] task {task_id} 启动: {len(fn_list)} 个漏报, project={pid} job={jid}')
