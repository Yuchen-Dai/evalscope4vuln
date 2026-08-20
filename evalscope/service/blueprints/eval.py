import json
import os
import pandas as pd
import uuid
from datetime import datetime
from flask import Blueprint, current_app, jsonify, request, send_file
from tabulate import tabulate
from typing import Any, Dict, List

from evalscope.api.registry import BENCHMARK_REGISTRY
from evalscope.config import TaskConfig
from evalscope.constants import EvalType
from evalscope.report.combinator import get_data_frame, get_report_list
from evalscope.utils.logger import get_logger
from ..utils import (
    OUTPUT_DIR,
    create_log_file,
    get_log_content,
    run_eval_wrapper,
    run_in_subprocess,
    serialize_result,
    stop_process,
    validate_task_id,
)
from ..utils.process import adopt_task, is_task_running, list_active_processes, start_subprocess
from ..utils.task_runtime import is_process_alive, patch_progress, proc_start_ticks, read_runtime, write_runtime

logger = get_logger()

bp_eval = Blueprint('eval', __name__, url_prefix='/api/v1/eval')


def _outputs_root() -> str:
    """invoke 产出目录：用前端 outputs_root（--outputs），保证 Dashboard/Reports/progress 都能读到结果。"""
    return current_app.config.get('OUTPUTS_ROOT') or OUTPUT_DIR


def _vuln_entry(name: str) -> Dict[str, Any]:
    """从 BENCHMARK_REGISTRY 的 BenchmarkMeta 构造一个 vuln benchmark entry（供前端展示）。"""
    meta = BENCHMARK_REGISTRY[name]
    return {
        'name': name,
        'pretty_name': meta.pretty_name or name,
        'tags': list(meta.tags or []),
        'category': 'llm',
        'subset_list': list(meta.subset_list or []),
        'total_samples': 0,
        'few_shot_num': meta.few_shot_num,
        'dataset_id': meta.dataset_id,
        'paper_url': meta.paper_url,
        'metrics': [],
        'meta': meta.to_string_dict(),
        'description': {
            'zh': {'full': meta.description or '', 'sections': {}},
            'en': {'full': meta.description or '', 'sections': {}},
        },
    }


_COLUMN_ZH = {
    'Model': '模型',
    'Dataset': '数据集',
    'Metric': '指标',
    'Subset': '子集',
    'Num': '数量',
    'Score': '得分',
}


def _build_result_table(work_dir: str) -> str:
    """Build a Markdown pipe-table from the JSON report files in *work_dir*/reports.

    Returns an empty string when no reports are found or on any error.
    """
    try:
        reports_dir = os.path.join(work_dir, 'reports')
        report_list = get_report_list([reports_dir])
        if not report_list:
            return ''
        df = get_data_frame(report_list, flatten_metrics=True, flatten_categories=True)
        _CAT_LEVEL_NAMES = ['类别', '子类别', '细分类别']
        new_cols = {}
        for col in df.columns:
            if col in _COLUMN_ZH:
                new_cols[col] = _COLUMN_ZH[col]
            elif col.startswith('Cat.'):
                try:
                    level = int(col[4:])
                    new_cols[col] = _CAT_LEVEL_NAMES[level] if level < len(_CAT_LEVEL_NAMES) else f'类别{level}'
                except ValueError:
                    new_cols[col] = col.replace('Cat.', '类别')
        df = df.rename(columns=new_cols)
        score_col = _COLUMN_ZH.get('Score', 'Score')
        if score_col in df.columns:
            df[score_col] = pd.to_numeric(df[score_col],
                                          errors='coerce').map(lambda x: f'{x:.4f}' if pd.notna(x) else '')
        return tabulate(df, headers=df.columns, tablefmt='pipe', showindex=False, disable_numparse=True)
    except Exception as e:
        logger.warning(f'Failed to build result table: {e}')
        return ''


_REQUIRED_FIELDS = ['datasets', 'scan_config']


class RequestValidationError(Exception):
    """Raised by _parse_request when the incoming request is invalid."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@bp_eval.errorhandler(RequestValidationError)
def _handle_validation_error(exc: RequestValidationError):
    return jsonify({'error': exc.message}), exc.status_code


def _parse_request(require_task_id: bool = True) -> tuple[dict, str]:
    """Validate the request body and return (data, task_id).

    The ``EvalScope-Task-Id`` header is optional when *require_task_id* is
    False — the service then generates the task_id itself (invoke flow).
    Resume flows keep it mandatory because they must reuse the original id.

    Raises:
        RequestValidationError: when the request is missing required fields or
            the ``EvalScope-Task-Id`` header is absent/malformed and required.
    """
    data = request.get_json()
    if not data:
        raise RequestValidationError('Request body is required')

    for field in _REQUIRED_FIELDS:
        if field not in data:
            raise RequestValidationError(f'{field} is required')

    task_id = request.headers.get('EvalScope-Task-Id') or None
    if not task_id and require_task_id:
        raise RequestValidationError('EvalScope-Task-Id header is required')

    if task_id:
        try:
            validate_task_id(task_id)
        except ValueError as e:
            raise RequestValidationError(str(e)) from e

    return data, task_id


def _generate_task_id() -> str:
    """Server-side task_id: timestamp + random suffix, collision-safe."""
    return f'task-{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}'


def _build_task_config(data: dict) -> TaskConfig:
    """Build a TaskConfig from request data with common defaults applied.

    漏洞测评专用：eval_type 固定 mock_llm（不加载真模型，run_inference 自行调图灵平台）；
    表单 scan_config（图灵扫描参数）透传到所选 benchmark 的 dataset_args[name]。
    每个 vuln_<name> benchmark 的 dataset_id 已在注册时指向 datasets/<name>/，无需补 local_path。
    """
    if not data.get('eval_type'):
        data['eval_type'] = EvalType.MOCK_LLM
    if not data.get('model'):
        # 用前端填的扫描模型名作为 evalscope 报告的"模型"列（没填则回退占位）
        scan_model = (data.get('scan_config') or {}).get('model_name', '')
        data['model'] = scan_model.strip() or 'default'
    # scan_config 不再走 dataset_args[name]（会被 BenchmarkMeta._update 过滤丢弃），
    # 改由 _write_scan_config 落盘 work_dir/scan_config.json，adapter 直接读文件。

    task_config = TaskConfig.from_dict(data)
    task_config.no_timestamp = True
    task_config.enable_progress_tracker = True
    task_config.analysis_report = False  # 不生成 LLM 分析报告（无 judge model）
    return task_config


def _all_results_empty(result) -> bool:
    """Return True when every dataset in the evaluation result produced no scores.

    This happens when ``ignore_errors=True`` and every sample failed: each
    dataset evaluator returns an empty dict instead of a :class:`Report`.
    """
    if not result:
        return True
    if isinstance(result, dict):
        return all(not v for v in result.values())
    if isinstance(result, list):
        return all(_all_results_empty(r) for r in result)
    return False


def _write_scan_config(work_dir: str, scan_config: dict) -> None:
    """把表单 scan_config 落盘到 work_dir/scan_config.json。

    dataset_args[name] 加载 benchmark 时会被 BenchmarkMeta._update 过滤掉非 meta
    字段（scan_config 会丢），改用文件透传给 adapter 的 record_to_sample。
    """
    os.makedirs(work_dir, exist_ok=True)
    with open(os.path.join(work_dir, 'scan_config.json'), 'w', encoding='utf-8') as f:
        json.dump(scan_config or {}, f, ensure_ascii=False)


def _start_task(task_id: str, task_config: TaskConfig):
    """异步：启动 run_task 子进程，立即返回（不阻塞）。

    子进程后台跑，进度经 progress.json、结果经 reports/ 落地。前端轮询
    /progress 和 /eval/tasks 查状态，/report 拿 HTML 报告。子进程 pid 落
    task_runtime.json，供崩溃/重启后的任务对账（reconcile）使用。
    """
    work_dir = task_config.work_dir
    create_log_file(task_id, os.path.join('logs', 'eval_log.log'), _outputs_root())
    proc = start_subprocess(run_eval_wrapper, task_config, task_id=task_id)
    write_runtime(work_dir, proc.pid, proc_start_ticks(proc.pid))
    logger.info(f'[{task_id}] Task started (async): model={task_config.model}, datasets={task_config.datasets}')
    return jsonify({'status': 'running', 'task_id': task_id}), 202


@bp_eval.route('/invoke', methods=['POST'])
def run_evaluation():
    """异步提交评测任务：立即返回 task_id，后台跑。

    task_id 由服务端生成（header 缺省时）；带 header 的旧客户端仍接受，
    但任何已存在的 work_dir 都会 409，杜绝复用已完结 task_id 覆盖旧产物。
    """
    data, task_id = _parse_request(require_task_id=False)
    if not task_id:
        task_id = _generate_task_id()

    work_dir = os.path.join(_outputs_root(), task_id)
    if os.path.exists(work_dir):
        return jsonify({'error': f'task_id already exists: {task_id}'}), 409
    if is_task_running(task_id):
        return jsonify({'error': f'Task {task_id} is already running'}), 409

    task_config = _build_task_config(data)
    task_config.work_dir = work_dir
    _write_scan_config(task_config.work_dir, data.get('scan_config') or {})
    return _start_task(task_id, task_config)


@bp_eval.route('/stop', methods=['POST'])
def stop_evaluation():
    """Stop a running evaluation task.

    Query params:
        task_id (str): the task identifier
    """
    task_id = request.args.get('task_id')
    if not task_id:
        return jsonify({'error': 'task_id is required'}), 400

    stopped = stop_process(task_id)
    if stopped:
        # The child is killed by signal, so it cannot write its own terminal
        # state — record it here so the task does not show up as running.
        patch_progress(os.path.join(_outputs_root(), task_id), 'stopped', 'Stopped by user')
        return jsonify({'status': 'stopped', 'task_id': task_id}), 200
    else:
        return jsonify({'error': f'No running task found for task_id: {task_id}'}), 404


@bp_eval.route('/resume/invoke', methods=['POST'])
def resume_evaluation():
    """异步恢复评测任务。"""
    data, task_id = _parse_request()
    if is_task_running(task_id):
        return jsonify({'error': f'Task {task_id} is already running'}), 409

    work_dir = os.path.join(_outputs_root(), task_id)
    if not os.path.isdir(work_dir):
        return jsonify({'error': f'Output directory not found for task_id: {task_id}'}), 404

    task_config = _build_task_config(data)
    task_config.work_dir = work_dir
    task_config.use_cache = work_dir
    task_config.rerun_review = True
    _write_scan_config(task_config.work_dir, data.get('scan_config') or {})
    return _start_task(task_id, task_config)


@bp_eval.route('/progress', methods=['GET'])
def get_evaluation_progress():
    """Get the real-time hierarchical progress of a running evaluation task.

    Query params:
        task_id (str): the task identifier
    """
    task_id = request.args.get('task_id')
    if not task_id:
        return jsonify({'error': 'task_id is required'}), 400

    progress_file = os.path.join(_outputs_root(), task_id, 'progress.json')
    try:
        with open(progress_file, 'r') as f:
            progress = json.load(f)
        # On-demand reconciliation: a stale "running" (child killed by OOM /
        # service restart) is detected here so the frontend stops spinning.
        if progress.get('status') == 'running' and not is_task_running(task_id):
            reconcile_running_task(task_id, os.path.dirname(progress_file))
            with open(progress_file, 'r') as f:
                progress = json.load(f)
        return jsonify(progress), 200
    except FileNotFoundError:
        return jsonify({'percent': 0.0}), 200
    except Exception as e:
        logger.error(f'Failed to get progress for task {task_id}: {e}')
        return jsonify({'error': str(e)}), 500


def _read_progress(task_id: str) -> dict:
    """读 task_id 的 progress.json（不存在/损坏返回 {percent: 0.0}）。"""
    progress_file = os.path.join(_outputs_root(), task_id, 'progress.json')
    try:
        with open(progress_file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'percent': 0.0}


def reconcile_running_task(task_id: str, work_dir: str) -> str:
    """对账一个 progress 标记 running 但不在内存注册表里的任务。

    progress.json 只由子进程在正常退出时写终态；OOM/SIGKILL/服务重启都会
    让它停在 running。这里按 task_runtime.json 记录的 pid 判定真实状态：

    - pid 仍活（孤儿进程，如服务重启后遗留）→ 收养（保持 running，stop
      仍可按 pid 杀），返回 'running'；
    - pid 已死/记录缺失 → 写 error 终态（progress.json），返回 'error'。

    updated_at 不参与判定：单样本扫描可数小时不动 percent，时间阈值会误杀。
    """
    if is_task_running(task_id):
        return 'running'
    runtime = read_runtime(work_dir)
    if runtime and is_process_alive(runtime.get('pid'), runtime.get('start_ticks')):
        adopt_task(task_id, runtime.get('pid'), runtime.get('start_ticks'))
        return 'running'
    patch_progress(work_dir, 'error', 'Child process died unexpectedly (service restart / OOM / crash).')
    return 'error'


def reconcile_stale_tasks(outputs_root: str) -> int:
    """启动对账：扫 outputs_root 下所有 running 状态的 progress.json。

    幂等——终态任务不动。返回本次处理的任务数（供日志/测试）。
    """
    import glob as _glob

    reconciled = 0
    for pf in _glob.glob(os.path.join(outputs_root, '*', 'progress.json')):
        task_id = os.path.basename(os.path.dirname(pf))
        try:
            with open(pf, encoding='utf-8') as f:
                status = (json.load(f) or {}).get('status')
        except (json.JSONDecodeError, OSError):
            continue
        if status != 'running':
            continue
        new_status = reconcile_running_task(task_id, os.path.dirname(pf))
        reconciled += 1
        if new_status == 'error':
            logger.warning(f'[reconcile] Task {task_id} marked error (child process gone).')
    return reconciled


def _read_task_meta(task_id: str, root: str) -> dict:
    """读任务展示元信息：project_name 来自 scan_config.json；model/dataset 来自
    report JSON（回退 task_config.yaml）。"""
    import glob as _glob
    meta: dict = {}
    # project_name：scan_config.json（eval.py 在 invoke 时写入）
    try:
        with open(os.path.join(root, task_id, 'scan_config.json'), encoding='utf-8') as f:
            meta['project_name'] = (json.load(f) or {}).get('project_name', '')
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        meta['project_name'] = ''
    # model + dataset：优先 report JSON（最准），回退 task_config.yaml
    for rj in _glob.glob(os.path.join(root, task_id, 'reports', '*', '*.json')):
        try:
            with open(rj, encoding='utf-8') as f:
                rep = json.load(f)
            meta['model'] = rep.get('model_name', '')
            meta['dataset'] = rep.get('dataset_name', '')
            return meta
        except Exception:
            continue
    import yaml
    cfg_path = os.path.join(root, task_id, 'configs', 'task_config.yaml')
    try:
        with open(cfg_path, encoding='utf-8') as f:
            cfg = yaml.safe_load(f) or {}
        datasets = cfg.get('datasets') or []
        meta['model'] = cfg.get('model', '')
        meta['dataset'] = datasets[0] if datasets else ''
    except Exception:
        meta.setdefault('model', '')
        meta.setdefault('dataset', '')
    return meta


@bp_eval.route('/tasks', methods=['GET'])
def list_tasks():
    """列出所有任务（运行中 + 历史），全局共享，供 Tasks 页/多用户查看。"""
    import glob as _glob
    root = _outputs_root()
    items = {}

    # 运行中：_active_processes（过滤 is_alive）
    for task_id, proc in list_active_processes():
        if not proc.is_alive():
            continue
        p = _read_progress(task_id)
        meta = _read_task_meta(task_id, root)
        items[task_id] = {
            'task_id': task_id,
            'status': 'running',
            'percent': p.get('percent', 0.0),
            'updated_at': p.get('updated_at', ''),
            'has_report': os.path.exists(os.path.join(root, task_id, 'reports', 'report.html')),
            'model': meta.get('model', ''),
            'dataset': meta.get('dataset', ''),
            'project_name': meta.get('project_name', ''),
        }

    # 历史：扫 progress.json（eval 强制开 tracker，每个任务都有）
    for pf in _glob.glob(os.path.join(root, '*', 'progress.json')):
        task_id = os.path.basename(os.path.dirname(pf))
        if task_id in items:
            continue  # 运行中优先
        p = _read_progress(task_id)
        status = p.get('status', 'completed')
        if status == 'running':
            # 按需对账：不在内存注册表的 running 任务实时查 pid，僵尸标 error
            status = reconcile_running_task(task_id, os.path.dirname(pf))
        meta = _read_task_meta(task_id, root)
        items[task_id] = {
            'task_id': task_id,
            'status': status,
            'percent': p.get('percent', 100.0 if status == 'completed' else 0.0),
            'updated_at': p.get('updated_at', ''),
            'has_report': os.path.exists(os.path.join(root, task_id, 'reports', 'report.html')),
            'model': meta.get('model', ''),
            'dataset': meta.get('dataset', ''),
            'project_name': meta.get('project_name', ''),
        }

    result = sorted(items.values(), key=lambda x: x.get('updated_at', ''), reverse=True)
    return jsonify({'tasks': result}), 200


@bp_eval.route('/report', methods=['GET'])
def get_evaluation_report():
    """Get the HTML evaluation report for a completed task.

    Query params:
        task_id (str): the task identifier
    """
    task_id = request.args.get('task_id')
    if not task_id:
        return jsonify({'error': 'task_id is required'}), 400

    try:
        validate_task_id(task_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    report_file = os.path.join(_outputs_root(), task_id, 'reports', 'report.html')
    if not os.path.exists(report_file):
        return jsonify({'error': f'Report not found for task_id: {task_id}'}), 404

    return send_file(report_file, mimetype='text/html')


@bp_eval.route('/log', methods=['GET'])
def get_evaluation_log():
    """Get evaluation log content with pagination.

    Query params:
        task_id    (str): the task identifier
        start_line (int, optional): if not provided, read last `page` lines from end
        page       (int): number of lines to read (default 500)

    Returns:
        dict with text, head_line, tail_line, total_lines
    """
    task_id = request.args.get('task_id')
    if not task_id:
        return jsonify({'error': 'task_id is required'}), 400

    start_line = request.args.get('start_line', type=int)
    page = request.args.get('page', 500, type=int)

    try:
        result = get_log_content(task_id, os.path.join('logs', 'eval_log.log'), start_line, page, _outputs_root())
        return jsonify(result), 200
    except Exception as e:
        logger.error(f'Failed to get evaluation log: {str(e)}')
        return jsonify({'error': str(e)}), 500


@bp_eval.route('/benchmarks', methods=['GET'])
def list_benchmarks():
    """Return the catalogue of supported vulnerability-discovery benchmarks.

    Only benchmarks registered with a ``vuln_`` prefix in ``BENCHMARK_REGISTRY``
    are exposed. They are returned under the ``text`` bucket (``multimodal`` is
    always empty) to keep the legacy two-bucket response shape the frontend
    expects. Each entry is built from the registry's ``BenchmarkMeta``.
    """
    try:
        # 动态：返回所有 vuln_* benchmark（从注册表，category=llm → text 桶）
        names = sorted(n for n in BENCHMARK_REGISTRY.list_keys() if n.startswith('vuln_'))
        entries = [_vuln_entry(n) for n in names]
        result = {
            'text': entries,
            'multimodal': [],
        }
        return jsonify(result), 200
    except Exception as e:
        logger.error(f'Failed to list benchmarks: {e}')
        return jsonify({'error': str(e)}), 500
