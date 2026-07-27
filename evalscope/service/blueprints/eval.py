import json
import os
import pandas as pd
from flask import Blueprint, current_app, jsonify, request, send_file
from tabulate import tabulate
from typing import Any, Dict, List

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
from evalscope.api.registry import BENCHMARK_REGISTRY
from ..utils.process import is_task_running, list_active_processes, start_subprocess

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


def _parse_request() -> tuple[dict, str]:
    """Validate the request body and return (data, task_id).

    Raises:
        RequestValidationError: when the request is missing required fields or
            the ``EvalScope-Task-Id`` header is absent or malformed.
    """
    data = request.get_json()
    if not data:
        raise RequestValidationError('Request body is required')

    for field in _REQUIRED_FIELDS:
        if field not in data:
            raise RequestValidationError(f'{field} is required')

    task_id = request.headers.get('EvalScope-Task-Id')
    if not task_id:
        raise RequestValidationError('EvalScope-Task-Id header is required')

    try:
        validate_task_id(task_id)
    except ValueError as e:
        raise RequestValidationError(str(e)) from e

    return data, task_id


def _build_task_config(data: dict) -> TaskConfig:
    """Build a TaskConfig from request data with common defaults applied.

    漏洞测评专用：eval_type 固定 mock_llm（不加载真模型，run_inference 自行调图灵平台）；
    表单 scan_config（图灵扫描参数）透传到所选 benchmark 的 dataset_args[name]。
    每个 vuln_<name> benchmark 的 dataset_id 已在注册时指向 datasets/<name>/，无需补 local_path。
    """
    if not data.get('eval_type'):
        data['eval_type'] = EvalType.MOCK_LLM
    if not data.get('model'):
        data['model'] = 'turing_scanner'
    # scan_config 透传到所选的每个 vuln_* benchmark（adapter 在 record_to_sample
    # 通过 self._task_config.dataset_args[self._benchmark_meta.name] 读取）
    scan_config = data.get('scan_config') or {}
    if scan_config:
        dataset_args = data.setdefault('dataset_args', {})
        for name in (data.get('datasets') or []):
            if name.startswith('vuln_'):
                dataset_args.setdefault(name, {})['scan_config'] = scan_config

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


def _start_task(task_id: str, task_config: TaskConfig):
    """异步：启动 run_task 子进程，立即返回（不阻塞）。

    子进程后台跑，进度经 progress.json、结果经 reports/ 落地。前端轮询
    /progress 和 /eval/tasks 查状态，/report 拿 HTML 报告。
    """
    create_log_file(task_id, os.path.join('logs', 'eval_log.log'), _outputs_root())
    start_subprocess(run_eval_wrapper, task_config, task_id=task_id)
    logger.info(f'[{task_id}] Task started (async): model={task_config.model}, datasets={task_config.datasets}')
    return jsonify({'status': 'running', 'task_id': task_id}), 202


@bp_eval.route('/invoke', methods=['POST'])
def run_evaluation():
    """异步提交评测任务：立即返回 task_id，后台跑。"""
    data, task_id = _parse_request()
    if is_task_running(task_id):
        return jsonify({'error': f'Task {task_id} is already running'}), 409

    task_config = _build_task_config(data)
    task_config.work_dir = os.path.join(_outputs_root(), task_id)
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
        items[task_id] = {
            'task_id': task_id,
            'status': 'running',
            'percent': p.get('percent', 0.0),
            'updated_at': p.get('updated_at', ''),
            'has_report': os.path.exists(os.path.join(root, task_id, 'reports', 'report.html')),
        }

    # 历史：扫 progress.json（eval 强制开 tracker，每个任务都有）
    for pf in _glob.glob(os.path.join(root, '*', 'progress.json')):
        task_id = os.path.basename(os.path.dirname(pf))
        if task_id in items:
            continue  # 运行中优先
        p = _read_progress(task_id)
        status = p.get('status', 'completed')
        items[task_id] = {
            'task_id': task_id,
            'status': status,
            'percent': p.get('percent', 100.0 if status == 'completed' else 0.0),
            'updated_at': p.get('updated_at', ''),
            'has_report': os.path.exists(os.path.join(root, task_id, 'reports', 'report.html')),
        }

    result = sorted(items.values(), key=lambda x: x.get('updated_at', ''), reverse=True)
    return jsonify({'tasks': result}), 200


# ---------------------------------------------------------------------------
# 图灵平台配置透传（供前端 platform / detect-types 自动补全下拉用）
# ---------------------------------------------------------------------------
import httpx as _httpx


def _turing_proxy(path: str, **params):
    """透传图灵平台 GET 接口（trust_env=False 绕过本机 socks 代理）。"""
    base = os.environ.get('TURING_URL', 'http://127.0.0.1:8088').rstrip('/')
    try:
        r = _httpx.get(f"{base}{path}", params=params, trust_env=False, timeout=10.0)
        r.raise_for_status()
        return jsonify(r.json()), 200
    except Exception as e:
        return jsonify({'error': f'图灵平台不可达: {e}'}), 502


@bp_eval.route('/turing/platforms', methods=['GET'])
def turing_platforms():
    """透传 GET /api/platforms（平台列表，前端 platform 下拉补全）。"""
    return _turing_proxy('/api/platforms')


@bp_eval.route('/turing/detect-types', methods=['GET'])
def turing_detect_types():
    """透传 GET /api/platforms/{platform}/detect-types（探测类型，前端多选补全）。"""
    platform = request.args.get('platform', 'web')
    return _turing_proxy(f'/api/platforms/{platform}/detect-types')


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
    """Return the catalogue of supported benchmarks with descriptions.

    The list is split into two categories: ``text`` (LLM-only) and
    ``multimodal`` (VLM).  Descriptions are loaded from the ``_meta`` JSON
    files and post-processed: the H1 title and the last H2 section are
    stripped, then the remainder is split into per-section blocks.

    The default catalogue can be overridden at application startup by setting
    ``app.config['SUPPORTED_BENCHMARKS']`` to a dict with keys ``'text'`` and
    ``'multimodal'``, each containing a list of benchmark names.

    Query params:
        type (str, optional): Filter to ``'text'`` or ``'multimodal'`` only.
        all (str, optional): When ``'true'``, return *all* benchmarks discovered
            from the ``_meta`` directory instead of the curated default lists.
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
