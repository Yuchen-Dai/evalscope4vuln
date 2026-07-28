# Copyright (c) Alibaba, Inc. and its affiliates.
"""Flask service for EvalScope evaluation and performance testing."""
import multiprocessing
import os
import threading
import time
from datetime import datetime
from flask import Flask, jsonify, send_from_directory

from evalscope.utils.logger import get_logger
from .blueprints import bp_eval, bp_reports
from .utils import OUTPUT_DIR as _DEFAULT_ROOT

logger = get_logger()


def _monitor_active_processes(interval: float = 2.0):
    """周期清理已结束的异步任务子进程（异步 invoke 完成检测）。

    子进程退出时 progress.json 已是终态（子进程内 ProgressTracker.__exit__ 写），
    这里只负责从 _active_processes 移除 + 释放 Process 资源。
    """
    from .utils.process import list_active_processes, unregister_process
    while True:
        for task_id, proc in list_active_processes():
            if not proc.is_alive():
                unregister_process(task_id)
                try:
                    proc.close()
                except Exception:
                    pass
                logger.info(f'[monitor] Task {task_id} finished, cleaned up.')
        time.sleep(interval)


# Path to the built React SPA (web/dist).  Resolved relative to the
# repository root so that ``pip install -e .`` works out of the box.
_WEB_DIST = os.path.join(os.path.dirname(__file__), '..', 'web', 'dist')
_WEB_DIST = os.path.abspath(_WEB_DIST)


def create_app(outputs: str = None):
    """Create and configure the Flask application.

    Args:
        outputs: Root directory for evaluation outputs. If provided, it will be
                 used as the default scan path in the web dashboard.
    """
    app = Flask(__name__)

    # Store the outputs path in app config so blueprints can access it
    if outputs:
        app.config['OUTPUTS_ROOT'] = os.path.abspath(outputs)
    else:
        # 默认输出目录：evalscope 包目录下 outputs/（自动创建，新机器开箱即用）
        default_outputs = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'outputs')
        os.makedirs(default_outputs, exist_ok=True)
        app.config['OUTPUTS_ROOT'] = default_outputs

    # Ensure non-ASCII characters (e.g. Chinese) are serialised as-is in JSON
    # responses instead of being escaped to \uXXXX sequences.
    app.json.ensure_ascii = False

    # --- CORS (development convenience) -----------------------------------
    try:
        from flask_cors import CORS
        CORS(app)
    except ImportError:
        pass  # flask-cors not installed; same-origin only

    # Register blueprints
    app.register_blueprint(bp_eval)
    app.register_blueprint(bp_reports)

    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint."""
        return jsonify({'status': 'ok', 'service': 'evalscope', 'timestamp': datetime.now().isoformat()})

    @app.route('/api/v1/config', methods=['GET'])
    def get_config():
        """Return runtime configuration for the frontend."""
        outputs_root = app.config.get('OUTPUTS_ROOT')
        return jsonify({
            'outputs_root': outputs_root or _DEFAULT_ROOT,
        })

    # --- SPA static-file serving ------------------------------------------
    if os.path.isdir(_WEB_DIST):

        @app.route('/', defaults={'path': ''})
        @app.route('/<path:path>')
        def serve_spa(path):
            """Serve the React SPA for all non-API routes."""
            file_path = os.path.join(_WEB_DIST, path)
            if path and os.path.isfile(file_path):
                return send_from_directory(_WEB_DIST, path)
            return send_from_directory(_WEB_DIST, 'index.html')

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'error': 'Endpoint not found',
            'available_endpoints': {
                'GET  /health': 'Health check',
                'GET  /api/v1/config': 'Get runtime configuration',
                'GET  /api/v1/reports/media/file': 'Serve a local media file (image/audio/video) by path',
                'POST /api/v1/eval/invoke': 'Run model evaluation task (blocking)',
                'GET  /api/v1/eval/benchmarks': 'List supported benchmarks with descriptions',
                'GET  /api/v1/eval/log': 'Get evaluation log',
                'GET  /api/v1/eval/progress': 'Get real-time evaluation progress',
                'GET  /api/v1/eval/report': 'Get HTML evaluation report',
                'POST /api/v1/eval/resume/invoke': 'Resume a previous evaluation (blocking)',
                'GET  /api/v1/reports/scan': 'Scan available report folders',
                'GET  /api/v1/reports/list': 'Filterable, paginated report listing',
                'GET  /api/v1/reports/load': 'Load a single report',
                'GET  /api/v1/reports/load_multi': 'Load multiple reports',
                'GET  /api/v1/reports/dataframe': 'Get report data as JSON table',
                'GET  /api/v1/reports/predictions': 'Get model predictions',
                'GET  /api/v1/reports/analysis': 'Get AI analysis text',
                'GET  /api/v1/reports/html': 'Get HTML report file',
            }
        }), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f'Internal server error: {str(error)}')
        return jsonify({'error': 'Internal server error', 'message': str(error)}), 500

    return app


def run_service(host: str = '0.0.0.0', port: int = 9000, debug: bool = False, outputs: str = None):
    """Run the Flask service.

    Args:
        outputs: Root directory for evaluation outputs. If provided, the web
                 dashboard will use this as the default scan path instead of
                 ``./outputs``.
    """

    # Force the multiprocessing start method to 'spawn' to avoid issues with
    # model loading in forked child processes on some platforms.
    multiprocessing.set_start_method('spawn', force=True)
    app = create_app(outputs=outputs)

    logger.info(f'Starting EvalScope service on {host}:{port}')
    logger.info('Available endpoints:')
    logger.info('  GET  /health                         - Health check')
    logger.info('  POST /api/v1/eval/invoke             - Run model evaluation task (blocking)')
    logger.info('  GET  /api/v1/eval/benchmarks         - List supported benchmarks with descriptions')
    logger.info('  GET  /api/v1/eval/log                - Get evaluation log')
    logger.info('  GET  /api/v1/eval/progress           - Get real-time evaluation progress')
    logger.info('  GET  /api/v1/eval/report             - Get HTML evaluation report')
    logger.info('  POST /api/v1/eval/resume/invoke      - Resume a previous evaluation (blocking)')
    logger.info('Refer to docs for parameters: https://evalscope.readthedocs.io/en/latest/user_guides/service.html')

    # Print a user-friendly dashboard URL
    display_host = host if host != '0.0.0.0' else '127.0.0.1'
    dashboard_url = f'http://{display_host}:{port}/dashboard'
    logger.info(f'Dashboard: {dashboard_url}')
    print(f'\n  🌐 EvalScope Dashboard: {dashboard_url}\n')

    # 启动 monitor 线程：周期清理已结束的异步任务子进程
    threading.Thread(target=_monitor_active_processes, daemon=True).start()
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    run_service()
