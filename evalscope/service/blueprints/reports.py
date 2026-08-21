"""Blueprint for report browsing and data access.

Exposes the file-system report data through a REST API so that the
React SPA frontend can load reports, predictions and analyses without
direct filesystem access.
"""
import asyncio
import httpx
import json
import mimetypes
import os
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from flask import Blueprint, jsonify, request, send_file
from typing import List

from evalscope.benchmarks.vuln_scan import config as vb_config
from evalscope.benchmarks.vuln_scan.analysis import fn_advisor, trace_view
from evalscope.benchmarks.vuln_scan.turing.client import TuringClient
from evalscope.constants import PLOTLY_CDN_URL, PLOTLY_THEME
from evalscope.metrics.judge.llm_judge import LLMJudge
from evalscope.report import ReportKey, get_data_frame
from evalscope.report.report import Report
from evalscope.report.visualization import (
    plot_multi_report_radar,
    plot_single_dataset_scores,
    plot_single_report_scores,
    plot_single_report_sunburst,
)
from evalscope.service.utils import fn_advice_runner
from evalscope.utils.data_utils import (
    get_acc_report_df,
    get_compare_report_df,
    get_model_prediction,
    get_report_analysis,
    get_vuln_scan_meta,
    load_multi_report,
    load_single_report,
    normalize_score,
    primary_metric,
    process_report_name,
    scan_for_report_folders,
)
from evalscope.utils.io_utils import OutputsStructure
from evalscope.utils.logger import get_logger
from ..utils import OUTPUT_DIR, validate_task_id

logger = get_logger()

bp_reports = Blueprint('reports', __name__, url_prefix='/api/v1/reports')

_DEFAULT_ROOT = OUTPUT_DIR

# Allowed extensions for the media proxy (security: do not serve arbitrary files)
_MEDIA_EXTENSIONS = {
    # image
    '.jpg',
    '.jpeg',
    '.png',
    '.gif',
    '.webp',
    '.bmp',
    '.svg',
    '.ico',
    # video
    '.mp4',
    '.webm',
    '.ogg',
    '.ogv',
    '.mov',
    '.avi',
    '.mkv',
    # audio
    '.mp3',
    '.wav',
    '.flac',
    '.aac',
    '.m4a',
    '.opus',
}


@bp_reports.route('/media/file', methods=['GET'])
def serve_media_file():
    """Serve a local media file (image / audio / video) via HTTP.

    This proxy endpoint allows the browser to load server-side local file
    paths that are stored inside prediction records (e.g. video paths from
    MVBench datasets).

    Query params:
        path (str): Absolute path to the media file on the server.

    Security:
        - Only files with known media extensions are served.
        - The file must exist, be a regular file and live under the
          server-side outputs root (rejects arbitrary absolute paths).
    """
    file_path = request.args.get('path', '').strip()
    if not file_path:
        return jsonify({'error': 'path parameter is required'}), 400

    # Normalise to absolute path and reject directory traversal
    file_path = os.path.realpath(file_path)

    root = os.path.realpath(_root_path())
    if os.path.commonpath([file_path, root]) != root:
        return jsonify({'error': 'Path is outside the outputs root'}), 403

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in _MEDIA_EXTENSIONS:
        return jsonify({'error': f'File type {ext!r} is not allowed'}), 403

    if not os.path.isfile(file_path):
        return jsonify({'error': 'File not found'}), 404

    mime_type, _ = mimetypes.guess_type(file_path)
    if mime_type is None:
        mime_type = 'application/octet-stream'

    return send_file(file_path, mimetype=mime_type)


def _root_path() -> str:
    # Security: the root is ALWAYS the server-side outputs root (--outputs).
    # It used to be overridable via the `root_path` query/body param, which let
    # any client point list/scan/delete at arbitrary directories. The frontend
    # only ever echoes back the value it fetched from /api/v1/config, so
    # ignoring the client-supplied value changes nothing for legitimate use.
    from flask import current_app
    return current_app.config.get('OUTPUTS_ROOT') or _DEFAULT_ROOT


def _apply_chart_theme(fig: go.Figure, theme: str) -> None:
    """Apply the Web console theme to a generated Plotly figure."""
    template = 'plotly_white' if theme == 'light' else PLOTLY_THEME
    fig.update_layout(template=template)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _df_to_records(df) -> list:
    """Convert a pandas DataFrame to a list of dicts, handling NaN."""
    if df is None or df.empty:
        return []
    return json.loads(df.to_json(orient='records', force_ascii=False))


def _extract_timestamp(report_name: str, root: str) -> str:
    """Try to extract a timestamp from the report directory name or fall back to mtime."""
    try:
        prefix, _, _ = process_report_name(report_name)
        # Directory names typically look like "20260423_201338"
        for fmt in ('%Y%m%d_%H%M%S', '%Y%m%d'):
            try:
                dt = datetime.strptime(prefix, fmt)
                return dt.isoformat()
            except ValueError:
                continue
        # Fall back to directory modification time
        dir_path = os.path.join(root, prefix)
        if os.path.isdir(dir_path):
            mtime = os.path.getmtime(dir_path)
            return datetime.fromtimestamp(mtime).isoformat()
    except Exception:
        pass
    return ''


def _primary_metric(r: Report):
    """主展示指标（vuln 报告为 Overall/Coverage，回退 metrics[0]）——见 data_utils.primary_metric。"""
    return primary_metric(r)


def _build_report_meta(report_name: str, root: str) -> dict:
    """Load a report and return lightweight metadata for the list endpoint."""
    try:
        # project_name is the unique turing project display name submitted per
        # run; it is persisted to <work_dir>/scan_config.json by eval.py at
        # invoke time (work_dir == root/<prefix>). Falls back to '' for legacy
        # / non-vuln reports lacking the file.
        prefix, _model, _datasets = process_report_name(report_name)
        project_name = _read_scan_config(os.path.join(root, prefix)).get('project_name', '')
        report_list, datasets, _ = load_single_report(root, report_name)
    except Exception:
        return None

    if not report_list:
        return None

    # Aggregate: use the first report's model_name; collect all dataset names
    first = report_list[0]
    total_num = 0
    dataset_names = []
    # 主展示指标逐 report 选取（读时选择，存量报告 metrics[0]=F1 也能切到 Coverage）
    primary = [_primary_metric(r) for r in report_list]
    for r in report_list:
        dataset_names.append(r.dataset_name)
        total_num += r.num or 0

    scores = [p[0] for p in primary]
    avg_score = round(sum(scores) / len(report_list), 4) if report_list else 0.0
    timestamp = _extract_timestamp(report_name, root)
    metric_names = [p[1] for p in primary]
    metric_name = metric_names[0] if len(metric_names) == len(report_list) and all(
        name == metric_names[0] for name in metric_names
    ) else ''

    # Preserve each metric's native scale; consumers use metric_name to format it.
    dataset_scores = {}
    for r, (p_score, _pn) in zip(report_list, primary):
        dataset_scores[r.dataset_name] = round(p_score, 4) if p_score is not None else None

    # Aggregate vuln-mining counts (TP/FP/FN) from the Overall/* metrics.
    # Non-vuln reports lack these entries; vuln_summary stays None so the
    # frontend degrades gracefully (shows '—' / hides the column).
    def _overall_metric(r, suffix):
        target = f'Overall/{suffix}'
        for m in r.metrics:
            if m.name == target:
                return m.score
        return None

    tp_sum = fp_sum = fn_sum = 0.0
    has_vuln = False
    for r in report_list:
        tp = _overall_metric(r, 'TP')
        fp = _overall_metric(r, 'FP')
        fn = _overall_metric(r, 'FN')
        if tp is None and fp is None and fn is None:
            continue
        has_vuln = True
        tp_sum += tp or 0.0
        fp_sum += fp or 0.0
        fn_sum += fn or 0.0

    vuln_summary = None
    if has_vuln:
        denom = tp_sum + fn_sum
        recall = round(tp_sum / denom, 4) if denom > 0 else 0.0
        vuln_summary = {
            'tp': int(tp_sum),
            'fp': int(fp_sum),
            'fn': int(fn_sum),
            'recall': recall,
        }

    return {
        'name': report_name,
        'model_name': first.model_name,
        'project_name': project_name,
        'dataset_name': ', '.join(dataset_names) if len(dataset_names) > 1 else
        (dataset_names[0] if dataset_names else ''),
        'score': avg_score,
        'metric_name': metric_name,
        'dataset_scores': dataset_scores,
        'num_samples': total_num,
        'timestamp': timestamp,
        'vuln_summary': vuln_summary,
        # keep individual scores for per-dataset filtering
        '_datasets': dataset_names,
        '_scores': scores,
    }


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------


@bp_reports.route('/delete', methods=['DELETE'])
def delete_report():
    """删除选中 report：按 report_name 解析 task_id，删整个任务目录（outputs_root/<task_id>/）。"""
    import shutil
    report_name = request.args.get('report_name')
    if not report_name:
        return jsonify({'error': 'report_name is required'}), 400
    task_id = report_name.split('@@')[0]
    try:
        validate_task_id(task_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    from ..utils.process import is_task_running
    if is_task_running(task_id):
        return jsonify({'error': f'Task {task_id} is still running; stop it before deleting'}), 409
    root = _root_path()
    abs_root = os.path.abspath(root)
    target = os.path.join(root, task_id)
    # 安全：target 必须在 root 下（防符号链接/路径逃逸），且确实存在
    if not os.path.isdir(target) or os.path.commonpath([os.path.abspath(target), abs_root]) != abs_root:
        return jsonify({'error': 'Invalid or missing task directory'}), 400
    shutil.rmtree(target)
    logger.info(f'Deleted report task directory: {target}')
    return jsonify({'status': 'ok', 'task_id': task_id}), 200


@bp_reports.route('/list', methods=['GET'])
def list_reports():
    """Return a filterable, paginated list of reports with metadata.

    Query params:
        root_path  (str):   output root directory (required)
        search     (str):   fuzzy search on project/dataset name
        projects   (str):   semicolon-separated project filter
        datasets   (str):   semicolon-separated dataset filter
        score_min  (float): minimum score (0-1)
        score_max  (float): maximum score (0-1)
        sort_by    (str):   score / project / dataset / time (default: time)
        sort_order (str):   asc / desc (default: desc)
        page       (int):   page number (default: 1)
        page_size  (int):   items per page (default: 20)
    """
    try:
        root = _root_path()
        if not root or not os.path.isdir(root):
            # 目录不存在（新机器/还没跑过任务）→ 返回空列表而非报错
            return jsonify({
                'reports': [],
                'total': 0,
                'page': 1,
                'page_size': 20,
                'filters': {
                    'available_projects': [],
                    'available_datasets': []
                },
            }), 200

        # --- Scan & load metadata ---
        raw_reports = scan_for_report_folders(root)
        items = []
        for rn in raw_reports:
            meta = _build_report_meta(rn, root)
            if meta is not None:
                items.append(meta)

        # Collect available filter values before filtering (drop empty
        # project_name so legacy reports don't surface a blank filter option).
        available_projects = sorted({it['project_name'] for it in items if it['project_name']})
        available_datasets = sorted({ds for it in items for ds in it['_datasets']})

        # --- Filters ---
        search = request.args.get('search', '').strip().lower()
        if search:
            items = [
                it for it in items if search in it['project_name'].lower() or search in it['model_name'].lower()
                or search in it['dataset_name'].lower()
            ]

        projects_filter = request.args.get('projects', '').strip()
        if projects_filter:
            project_set = {p.strip().lower() for p in projects_filter.split(';') if p.strip()}
            items = [it for it in items if it['project_name'].lower() in project_set]

        datasets_filter = request.args.get('datasets', '').strip()
        if datasets_filter:
            ds_set = {d.strip().lower() for d in datasets_filter.split(';') if d.strip()}
            items = [it for it in items if any(d.lower() in ds_set for d in it['_datasets'])]

        score_min = request.args.get('score_min', type=float)
        score_max = request.args.get('score_max', type=float)
        if score_min is not None:
            items = [it for it in items if it['score'] >= score_min]
        if score_max is not None:
            items = [it for it in items if it['score'] <= score_max]

        # --- Sort ---
        sort_by = request.args.get('sort_by', 'time')
        sort_order = request.args.get('sort_order', 'desc')
        reverse = sort_order == 'desc'

        sort_key_map = {
            'score': lambda x: x['score'],
            'project': lambda x: x['project_name'].lower(),
            'dataset': lambda x: x['dataset_name'].lower(),
            'time': lambda x: x['timestamp'],
        }
        key_fn = sort_key_map.get(sort_by, sort_key_map['time'])
        items.sort(key=key_fn, reverse=reverse)

        # --- Paginate ---
        page = max(1, request.args.get('page', 1, type=int))
        page_size = max(1, min(100, request.args.get('page_size', 20, type=int)))
        total = len(items)
        start = (page - 1) * page_size
        page_items = items[start:start + page_size]

        # Strip internal keys before returning
        for it in page_items:
            it.pop('_datasets', None)
            it.pop('_scores', None)

        return jsonify({
            'reports': page_items,
            'total': total,
            'page': page,
            'page_size': page_size,
            'filters': {
                'available_projects': available_projects,
                'available_datasets': available_datasets,
            },
        }), 200

    except Exception as e:
        logger.error(f'Failed to list reports: {e}')
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/scan', methods=['GET'])
def scan_reports():
    """Scan the output directory for available report folders.

    Query params:
        root_path (str): directory to scan (default: OUTPUT_DIR)
    """
    try:
        root = _root_path()
        reports = scan_for_report_folders(root)
        return jsonify({'reports': reports}), 200
    except Exception as e:
        logger.error(f'Failed to scan reports: {e}')
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/load', methods=['GET'])
def load_report():
    """Load a single report by name.

    Query params:
        root_path   (str): output root directory
        report_name (str): report identifier
    """
    report_name = request.args.get('report_name')
    if not report_name:
        return jsonify({'error': 'report_name is required'}), 400

    try:
        root = _root_path()
        report_list, datasets, task_cfg = load_single_report(root, report_name)
        return jsonify({
            'report_list': [r.to_dict() for r in report_list],
            'datasets': datasets,
            'task_config': task_cfg,
        }), 200
    except Exception as e:
        logger.error(f'Failed to load report {report_name}: {e}')
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/load_multi', methods=['GET'])
def load_multi():
    """Load multiple reports at once.

    Query params:
        root_path    (str): output root directory
        report_names (str): semicolon-separated report identifiers
    """
    names_raw = request.args.get('report_names', '')
    if not names_raw:
        return jsonify({'error': 'report_names is required'}), 400

    names = [n.strip() for n in names_raw.split(';') if n.strip()]
    try:
        root = _root_path()
        report_list = load_multi_report(root, names)
        return jsonify({
            'report_list': [r.to_dict() for r in report_list],
        }), 200
    except Exception as e:
        logger.error(f'Failed to load multi reports: {e}')
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/dataframe', methods=['GET'])
def get_dataframe():
    """Get report data as a flat JSON table.

    Query params:
        root_path        (str): output root directory
        report_name      (str): report identifier
        type             (str): 'acc' (accuracy overview) | 'compare' (pivot) | 'dataset' (single dataset)
        dataset_name     (str): required when type=dataset
    """
    report_name = request.args.get('report_name')
    if not report_name:
        return jsonify({'error': 'report_name is required'}), 400

    df_type = request.args.get('type', 'acc')
    dataset_name = request.args.get('dataset_name', '')

    try:
        root = _root_path()
        report_list, datasets, _ = load_single_report(root, report_name)
        acc_df, _ = get_acc_report_df(report_list)

        if df_type == 'compare':
            df, _ = get_compare_report_df(acc_df)
        elif df_type == 'dataset':
            if not dataset_name:
                return jsonify({'error': 'dataset_name is required for type=dataset'}), 400
            report_df = get_data_frame(report_list=report_list, flatten_metrics=True, flatten_categories=True)
            from evalscope.utils.data_utils import get_single_dataset_df
            df, _ = get_single_dataset_df(report_df, dataset_name)
        else:
            df = acc_df

        return jsonify({
            'columns': list(df.columns),
            'data': _df_to_records(df),
        }), 200
    except Exception as e:
        logger.error(f'Failed to get dataframe: {e}')
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/predictions', methods=['GET'])
def get_predictions():
    """Get model predictions for a given subset.

    Query params:
        root_path    (str): output root directory
        report_name  (str): report identifier
        dataset_name (str): dataset name
        subset_name  (str): subset name
    """
    report_name = request.args.get('report_name')
    dataset_name = request.args.get('dataset_name')
    subset_name = request.args.get('subset_name')

    if not all([report_name, dataset_name, subset_name]):
        return jsonify({'error': 'report_name, dataset_name and subset_name are required'}), 400

    try:
        root = _root_path()
        prefix, model_name, _ = process_report_name(report_name)
        work_dir = os.path.join(root, prefix)
        df = get_model_prediction(work_dir, model_name, dataset_name, subset_name)
        return jsonify({
            'predictions': _df_to_records(df),
        }), 200
    except Exception as e:
        logger.error(f'Failed to get predictions: {e}')
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/analysis', methods=['GET'])
def get_analysis():
    """Get the AI analysis text for a dataset.

    Query params:
        root_path    (str): output root directory
        report_name  (str): report identifier
        dataset_name (str): dataset name
    """
    report_name = request.args.get('report_name')
    dataset_name = request.args.get('dataset_name')

    if not report_name or not dataset_name:
        return jsonify({'error': 'report_name and dataset_name are required'}), 400

    try:
        root = _root_path()
        report_list, _, _ = load_single_report(root, report_name)
        analysis = get_report_analysis(report_list, dataset_name)
        return jsonify({'analysis': analysis}), 200
    except Exception as e:
        logger.error(f'Failed to get analysis: {e}')
        return jsonify({'error': str(e)}), 500


# ------------------------------------------------------------------
# FN 漏报 LLM-as-judge 路径分析（/fn-advice）
# ------------------------------------------------------------------


def _run_async(coro):
    """在 Flask 同步请求里跑 async（拉图灵 sessions + judge 调用）。"""
    try:
        asyncio.get_running_loop()
        import threading
        box = [None]

        def _r():
            box[0] = asyncio.run(coro)

        t = threading.Thread(target=_r)
        t.start()
        t.join()
        return box[0]
    except RuntimeError:
        return asyncio.run(coro)


def _read_scan_config(work_dir: str) -> dict:
    try:
        with open(os.path.join(work_dir, 'scan_config.json'), encoding='utf-8') as f:
            return json.load(f) or {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _load_judge_config() -> dict | None:
    """judge 模型配置：全局 judge_config.json 优先，环境变量兜底。未配返回 None。

    全局配置由 /api/v1/settings/judge 写入 <outputs_root>/judge_config.json，
    评测前后均可配置（不再依赖 per-task scan_config.json）。
    """
    from flask import current_app
    cfg_path = os.path.join(current_app.config.get('OUTPUTS_ROOT') or OUTPUT_DIR, 'judge_config.json')
    cfg = {}
    try:
        with open(cfg_path, encoding='utf-8') as f:
            cfg = json.load(f) or {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    api_url = cfg.get('api_url') or os.environ.get('VULN_JUDGE_API_URL')
    api_key = cfg.get('api_key') or os.environ.get('VULN_JUDGE_API_KEY')
    model_id = cfg.get('model_id') or os.environ.get('VULN_JUDGE_MODEL')
    if not (api_url and model_id):
        return None
    return {'api_url': api_url, 'api_key': api_key or 'EMPTY', 'model_id': model_id}


def _fn_advice_path(root: str, prefix: str, dataset_name: str) -> str:
    return os.path.join(root, prefix, 'fn_advice', f'{dataset_name}.json')


def _load_fn_advice(root: str, prefix: str, dataset_name: str) -> dict:
    """读主结果文件并叠加 MCP staging（fn-result-sink 写的 .mcp/*.json）。

    staging 是 agent 经 MCP submit_result 落盘的增量结果（执行与查看解耦）：主文件无该
    gt_id、主条目非 ok、或 staging 更新（ts 更大）且 ok 时覆盖；_save_fn_advice 的
    读-改-写会天然把 staging 收编进主文件。
    """
    path = _fn_advice_path(root, prefix, dataset_name)
    data: dict = {}
    if os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f) or {}
        except (json.JSONDecodeError, OSError):
            data = {}
    staging_dir = os.path.join(os.path.dirname(path), '.mcp')
    if not os.path.isdir(staging_dir):
        return data
    for name in os.listdir(staging_dir):
        if not name.endswith('.json'):
            continue
        try:
            with open(os.path.join(staging_dir, name), encoding='utf-8') as f:
                entry = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(entry, dict) or not entry.get('gt_id'):
            continue
        gt_id = entry.get('gt_id')
        cur = data.get(gt_id)
        if cur is None or cur.get('status') != 'ok' or \
                (entry.get('status') == 'ok' and int(entry.get('ts') or 0) > int(cur.get('ts') or 0)):
            data[gt_id] = entry
    return data


def _save_fn_advice(root: str, prefix: str, dataset_name: str, result: dict) -> None:
    path = _fn_advice_path(root, prefix, dataset_name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = _load_fn_advice(root, prefix, dataset_name)
    data[result.get('gt_id')] = result
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


@bp_reports.route('/fn-advice', methods=['GET'])
def get_fn_advice():
    """读取已缓存的 FN 漏报分析结果（前端初次加载用）。"""
    report_name = request.args.get('report_name')
    dataset_name = request.args.get('dataset_name')
    root = _root_path()
    if not report_name or not dataset_name:
        return jsonify({'error': 'report_name and dataset_name are required'}), 400
    try:
        prefix, _, _ = process_report_name(report_name)
        return jsonify({'advice': _load_fn_advice(root, prefix, dataset_name)}), 200
    except Exception as e:
        logger.error(f'get fn-advice failed: {e}')
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/fn-advice/invoke', methods=['POST'])
def invoke_fn_advice():
    """异步起 FN 漏报分析任务（线程），立即返回。前端轮询 /progress。

    JSON body: {root_path?, report_name, dataset_name, gt_ids?}；header EvalScope-Task-Id。
    gt_ids 省略 → 全量漏报；给定 → 只分析子集（单条也走异步，不再有同步阻塞端点）。
    judge 未配 / 老报告无 pid,jid → 200 + status:error（不起任务）。
    """
    data = request.get_json(silent=True) or {}
    report_name = data.get('report_name')
    dataset_name = data.get('dataset_name')
    gt_ids = data.get('gt_ids') or None
    root = _root_path()  # body root_path ignored (server-side outputs root only)
    if not report_name or not dataset_name:
        return jsonify({'error': 'report_name and dataset_name are required'}), 400
    task_id = request.headers.get('EvalScope-Task-Id', '')
    try:
        validate_task_id(task_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    try:
        prefix, model_name, _ = process_report_name(report_name)
        work_dir = os.path.join(root, prefix)
        meta = get_vuln_scan_meta(work_dir, model_name, dataset_name)
        vm = meta.get('vuln_match')
        if not vm:
            return jsonify({'error': '无 vuln_match（非 vuln benchmark 或缓存缺失）'}), 400
        fn_list = fn_advisor.extract_fn(vm)
        if not fn_list:
            return jsonify({'error': '该数据集无漏报(FN)漏洞'}), 400
        if gt_ids:
            want = {str(g) for g in gt_ids}
            fn_list = [g for g in fn_list if str(g.get('gt_id')) in want]
            if not fn_list:
                return jsonify({'error': 'gt_ids 未命中该数据集的任何漏报'}), 400
        jcfg = _load_judge_config()
        if not jcfg:
            return jsonify({'status': 'error', 'error': 'judge 模型未配置（点击右上角 ⚙ 设置中配置）'}), 200
        pid, jid = meta.get('project_id'), meta.get('job_id')
        if _read_scan_config(work_dir).get('sessions_file'):
            # 离线报告虽可能带真实 pid/jid，但平台连不上其来源图灵，FN 分析无法工作
            return jsonify({'status': 'error', 'error': '离线导入报告不支持 FN 分析（无图灵 job 上下文，需在线扫描报告）'}), 200
        if not pid or not jid:
            return jsonify({'status': 'error', 'error': '该报告无 project_id/job_id（老报告，需重跑评测以持久化）'}), 200
        if fn_advice_runner.is_fn_task_running_by_prefix(root, prefix, dataset_name):
            return jsonify({'error': '该数据集已有 FN 分析任务在运行'}), 409
        base_url = _read_scan_config(work_dir).get('turing_base_url') or vb_config.TURING_BASE_URL
        # 预写 running：worker 接管前（asyncio.run 启动有延迟），前端首次 poll 即可见进度
        fn_advice_runner._write_fn_progress(
            root,
            prefix,
            dataset_name,
            status='running',
            task_id=task_id,
            total_count=len(fn_list),
            processed_count=0,
            percent=0.0
        )
        fn_advice_runner.start_fn_task(
            task_id, root, prefix, dataset_name, fn_list, pid, jid, jcfg, meta.get('source_path', ''), base_url
        )
        return jsonify({'status': 'running', 'task_id': task_id}), 202
    except Exception as e:
        logger.error(f'fn-advice invoke failed: {e}', exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/fn-advice/progress', methods=['GET'])
def fn_advice_progress():
    """读取 FN 分析任务进度（按 report+dataset 维度，前端切走切回判 running）。"""
    report_name = request.args.get('report_name')
    dataset_name = request.args.get('dataset_name')
    root = _root_path()
    if not report_name or not dataset_name:
        return jsonify({'error': 'report_name and dataset_name are required'}), 400
    try:
        prefix, _, _ = process_report_name(report_name)
        return jsonify(fn_advice_runner._read_fn_progress(root, prefix, dataset_name)), 200
    except Exception as e:
        logger.error(f'fn-advice progress failed: {e}')
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/fn-advice/stop', methods=['POST'])
def stop_fn_advice():
    """停止 FN 分析任务（worker 下个 gt_id 边界退出，已完成结果已落盘）。"""
    task_id = request.args.get('task_id', '')
    if not task_id:
        return jsonify({'error': 'task_id is required'}), 400
    ok = fn_advice_runner.stop_fn_task(task_id)
    return jsonify({'status': 'ok' if ok else 'not_found', 'task_id': task_id}), 200


@bp_reports.route('/trace/for-finding', methods=['GET'])
def trace_for_finding():
    """按 finding 关联各阶段 session（mine/verify/detect）→ opencode part 适配 step + 统计。

    query: {root_path?, report_name, dataset_name, task_id, finding_id?, vuln_type?}
    纯展示，不跑 LLM。返回 {stages:{mine/verify/detect:[{task_id,task_type,steps[]}]}, stats}。
    """
    report_name = request.args.get('report_name')
    dataset_name = request.args.get('dataset_name')
    task_id = request.args.get('task_id')
    finding_id = request.args.get('finding_id')
    vuln_type = request.args.get('vuln_type')
    detection_id = request.args.get('detection_id')
    detection_source_task_id = request.args.get('detection_source_task_id')
    root = _root_path()
    if not report_name or not dataset_name or not task_id:
        return jsonify({'error': 'report_name, dataset_name, task_id are required'}), 400
    try:
        prefix, model_name, _ = process_report_name(report_name)
        work_dir = os.path.join(root, prefix)
        meta = get_vuln_scan_meta(work_dir, model_name, dataset_name)
        sessions = _get_sessions_for_report(work_dir, meta)
        if not sessions:
            return jsonify({'error': '该报告无 project_id/job_id 且未配置 sessions_file（老报告，需重跑评测）'}), 400
        traj = trace_view.sessions_to_trajectory(
            sessions, task_id, finding_id, vuln_type, detection_id, detection_source_task_id
        )
        return jsonify(traj), 200
    except Exception as e:
        logger.error(f'trace/for-finding failed: {e}', exc_info=True)
        return jsonify({'error': str(e)}), 500


# 跨模型轨迹对比：sessions 按 (project_id, job_id) 缓存——同一 report 的多个 gt 共享
# 同一份 job sessions，避免 N 模型 × M 漏洞 的 N×M 次图灵调用。sessions 不随时间变化。
_SESSIONS_CACHE: dict[tuple[str, str], tuple[float, list]] = {}
_SESSIONS_TTL = 600  # 秒


def _get_sessions_cached(pid: str, jid: str, base_url: str) -> list:
    """按 (pid,jid) 缓存图灵 job sessions（带 TTL）。"""
    import time
    key = (pid, jid)
    now = time.time()
    hit = _SESSIONS_CACHE.get(key)
    if hit and now - hit[0] < _SESSIONS_TTL:
        return hit[1]

    async def _fetch():
        client = TuringClient(base_url=base_url)
        try:
            await client.login(vb_config.TURING_USERNAME, vb_config.TURING_PASSWORD)
            return await client.get_job_sessions(pid, jid)
        finally:
            await client.aclose()

    sessions = (_run_async(_fetch()) or {}).get('sessions') or []
    _SESSIONS_CACHE[key] = (now, sessions)
    return sessions


# 离线导入报告（scan_config.sessions_file，无 pid/jid）：sessions 导出文件按 (path, mtime) 缓存
_SESSIONS_FILE_CACHE: dict[str, tuple[float, list]] = {}


def _get_sessions_for_report(work_dir: str, meta: dict) -> list:
    """取报告对应的 job sessions：离线报告（sessions_file）读本地；在线按 pid/jid 拉图灵。

    sessions_file 优先：离线导出虽带真实 pid/jid，但平台侧连不上其来源图灵，
    必须用本地文件。导出文件几十 MB，按 mtime 缓存只读一次（TraceCompareTab
    同 report 多 gt 共享）。两者都没有 → 空列表（调用方按 unavailable 处理）。
    """
    sf = _read_scan_config(work_dir).get('sessions_file') or ''
    if sf and os.path.isfile(sf):
        import time
        mtime = os.path.getmtime(sf)
        hit = _SESSIONS_FILE_CACHE.get(sf)
        if hit and hit[0] == mtime:
            return hit[1]
        try:
            with open(sf, encoding='utf-8') as f:
                sessions = (json.load(f) or {}).get('sessions') or []
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f'read sessions_file failed ({sf}): {e}')
            return []
        _SESSIONS_FILE_CACHE[sf] = (mtime, sessions)
        return sessions
    pid, jid = meta.get('project_id'), meta.get('job_id')
    if pid and jid:
        base_url = _read_scan_config(work_dir).get('turing_base_url') or vb_config.TURING_BASE_URL
        return _get_sessions_cached(pid, jid, base_url)
    return []


@bp_reports.route('/compare/trace', methods=['POST'])
def compare_trace():
    """跨模型挖掘轨迹对比：同一 gt_id 下各 report 的挖掘轨迹（前端并排对照用）。

    body: {root_path?, report_names: [...], dataset_name, gt_id}
    per-report: vuln_match.type.matches 找 gt_id→finding_id；finding_id→task_id 从 sessions 反查
    （findings_raw 无 task_id）→ sessions_to_trajectory。
    返回 {gt_id, runs:[{report_name, display_label, status: tp|fn|unavailable, trajectory?, reason?}]}。
    纯展示，无 LLM；FP 无 gt 锚点不纳入。
    """
    body = request.get_json(silent=True) or {}
    root = _root_path()  # body root_path ignored (server-side outputs root only)
    report_names = body.get('report_names') or []
    dataset_name = body.get('dataset_name')
    gt_id = body.get('gt_id')
    if not report_names or not dataset_name or not gt_id:
        return jsonify({'error': 'report_names, dataset_name, gt_id are required'}), 400
    try:
        runs: list[dict] = []
        for name in report_names:
            run: dict = {'report_name': name}
            try:
                prefix, model_name, _ds = process_report_name(name)
                run['display_label'] = model_name or name
                work_dir = os.path.join(root, prefix)
                meta = get_vuln_scan_meta(work_dir, model_name, dataset_name)
            except Exception as e:
                runs.append({**run, 'status': 'unavailable', 'reason': f'读取报告失败: {e}'})
                continue
            vm = meta.get('vuln_match') or {}
            vtype = vm.get('type') or {}
            matches = vtype.get('matches') or []
            missed = vtype.get('missed_gt') or []
            hit = next((m for m in matches if m.get('gt_id') == gt_id), None)
            sessions = _get_sessions_for_report(work_dir, meta)
            if not sessions:
                runs.append({
                    **run, 'status': 'unavailable',
                    'reason': '该报告无 project_id/job_id 且未配置 sessions_file（老报告，需重跑评测）'
                })
            elif hit:
                finding_id = hit.get('finding_id')
                info = trace_view.extract_finding_task_map(sessions).get(finding_id) or {}
                gt_list = vm.get('gt') or []
                gt_vuln_type = next((g.get('vuln_type') for g in gt_list if g.get('gt_id') == gt_id), None) \
                    or info.get('vuln_type')
                traj = trace_view.sessions_to_trajectory(
                    sessions, info.get('task_id'), finding_id, gt_vuln_type, info.get('detection_id'),
                    info.get('detection_source_task_id')
                )
                runs.append({**run, 'status': 'tp', 'trajectory': traj})
            elif gt_id in missed:
                runs.append({**run, 'status': 'fn', 'reason': '该模型未挖到此漏洞（漏报）'})
            else:
                runs.append({**run, 'status': 'unavailable', 'reason': '该报告数据集无此 gt'})
        return jsonify({'gt_id': gt_id, 'runs': runs}), 200
    except Exception as e:
        logger.error(f'compare/trace failed: {e}', exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/html', methods=['GET'])
def get_html_report():
    """Serve the HTML report file for a given report.

    Query params:
        root_path   (str): output root directory
        report_name (str): report identifier
    """
    report_name = request.args.get('report_name')
    if not report_name:
        return jsonify({'error': 'report_name is required'}), 400

    try:
        root = os.path.abspath(_root_path())
        prefix, model_name, _ = process_report_name(report_name)
        report_html = os.path.join(root, prefix, OutputsStructure.REPORTS_DIR, 'report.html')

        if not os.path.exists(report_html):
            return jsonify({
                'error': 'Report not yet generated',
                'message': 'The HTML report has not been generated for this evaluation. It may still be in progress.',
            }), 404

        return send_file(report_html, mimetype='text/html')
    except Exception as e:
        logger.error(f'Failed to get HTML report: {e}')
        return jsonify({'error': str(e)}), 500


@bp_reports.route('/chart', methods=['GET'])
def get_chart():
    """Generate an interactive Plotly chart as standalone HTML.

    Query params:
        root_path    (str): output root directory
        report_name  (str): report identifier (single report)
        report_names (str): semicolon-separated report identifiers (multi report)
        chart_type   (str): 'scores' | 'sunburst' | 'dataset_scores' | 'radar' | 'histogram' | 'grouped_bar'
        dataset_name (str): required for chart_type=dataset_scores
        subset_name  (str): required for chart_type=histogram
        theme        (str): 'light' | 'dark'; defaults to the existing dark report theme
    """
    chart_type = request.args.get('chart_type', 'scores')
    root = _root_path()

    try:
        fig = None

        if chart_type == 'radar':
            names_raw = request.args.get('report_names', '')
            names = [n.strip() for n in names_raw.split(';') if n.strip()]
            if not names:
                # Fall back to singular report_name
                single = request.args.get('report_name', '').strip()
                if single:
                    names = [single]
                else:
                    return jsonify({'error': 'report_names or report_name is required for radar'}), 400
            report_list = load_multi_report(root, names)
            acc_df, _ = get_acc_report_df(report_list)
            fig = plot_multi_report_radar(acc_df)
        elif chart_type == 'grouped_bar':
            # Grouped bar chart for multi-model comparison
            names_raw = request.args.get('report_names', '')
            names = [n.strip() for n in names_raw.split(';') if n.strip()]
            if not names:
                return jsonify({'error': 'report_names is required for grouped_bar'}), 400
            report_list = load_multi_report(root, names)
            acc_df, _ = get_acc_report_df(report_list)
            color_seq = ['#816DF8', '#0F9C7E', '#fbbf24', '#a78bfa', '#63b3ed']
            fig = px.bar(
                acc_df,
                x=ReportKey.model_name,
                y=ReportKey.score,
                color=ReportKey.dataset_name,
                barmode='group',
                text=ReportKey.score,
                color_discrete_sequence=color_seq,
            )
            fig.update_traces(texttemplate='%{text:.2f}', textposition='outside')
            fig.update_layout(
                template=PLOTLY_THEME,
                uniformtext_minsize=12,
                uniformtext_mode='hide',
                yaxis=dict(range=[0, 1]),
                margin=dict(t=20, l=20, r=20, b=20),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
            )
        elif chart_type == 'histogram':
            # Score distribution histogram from prediction NScore values
            report_name = request.args.get('report_name')
            dataset_name = request.args.get('dataset_name', '')
            subset_name = request.args.get('subset_name', '')
            if not report_name or not dataset_name or not subset_name:
                return jsonify({'error': 'report_name, dataset_name and subset_name are required for histogram'}), 400
            prefix, model_name, _ = process_report_name(report_name)
            work_dir = os.path.join(root, prefix)
            pred_df = get_model_prediction(work_dir, model_name, dataset_name, subset_name)
            if pred_df is not None and not pred_df.empty and 'NScore' in pred_df.columns:
                fig = px.histogram(
                    pred_df,
                    x='NScore',
                    nbins=20,
                    color_discrete_sequence=['#816DF8'],
                )
                fig.update_layout(
                    template=PLOTLY_THEME,
                    xaxis_title='Score',
                    yaxis_title='Count',
                    margin=dict(t=20, l=20, r=20, b=20),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                )
        else:
            report_name = request.args.get('report_name')
            if not report_name:
                return jsonify({'error': 'report_name is required'}), 400
            report_list, datasets, _ = load_single_report(root, report_name)
            acc_df, _ = get_acc_report_df(report_list)

            if chart_type == 'sunburst':
                fig = plot_single_report_sunburst(report_list)
            elif chart_type == 'dataset_scores':
                dataset_name = request.args.get('dataset_name', '')
                if not dataset_name:
                    return jsonify({'error': 'dataset_name is required for dataset_scores'}), 400
                report_df = get_data_frame(report_list=report_list, flatten_metrics=True, flatten_categories=True)
                from evalscope.utils.data_utils import get_single_dataset_df
                ds_df, _ = get_single_dataset_df(report_df, dataset_name)
                fig = plot_single_dataset_scores(ds_df)
            else:
                fig = plot_single_report_scores(acc_df)

        if fig is None:
            return '<html><body style="background:#0f172a;color:#94a3b8;display:flex;align-items:center;' \
                   'justify-content:center;height:100vh;font-family:sans-serif;">No data to plot</body></html>', \
                   200, {'Content-Type': 'text/html'}

        _apply_chart_theme(fig, request.args.get('theme', 'dark'))
        html = fig.to_html(full_html=True, include_plotlyjs=False, config={'responsive': True})
        plotly_script = f'<script src="{PLOTLY_CDN_URL}" charset="utf-8"></script>'
        html = html.replace('</head>', f'  {plotly_script}\n</head>')
        return html, 200, {'Content-Type': 'text/html'}

    except Exception as e:
        logger.error(f'Failed to generate chart: {e}')
        return jsonify({'error': str(e)}), 500
