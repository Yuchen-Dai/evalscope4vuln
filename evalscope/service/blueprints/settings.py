# Copyright (c) Alibaba, Inc. and its affiliates.
"""全局设置 blueprint。

judge 模型配置等全局项存 ``<outputs_root>/judge_config.json``，内网多用户共享
一份（服务端化，无状态）。fn-advice 等后置分析从此处读取，评测前后均可配置。
"""
import json
import os
from flask import Blueprint, current_app, jsonify, request

from evalscope.utils.logger import get_logger

from ..utils import OUTPUT_DIR

logger = get_logger()

bp_settings = Blueprint('settings', __name__, url_prefix='/api/v1/settings')

_JUDGE_CONFIG_FILE = 'judge_config.json'


def _config_path() -> str:
    root = current_app.config.get('OUTPUTS_ROOT') or OUTPUT_DIR
    return os.path.join(root, _JUDGE_CONFIG_FILE)


def _read_judge_config() -> dict:
    path = _config_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f) or {}
    except (json.JSONDecodeError, OSError):
        return {}


def _write_judge_config(cfg: dict) -> None:
    path = _config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


@bp_settings.route('/judge', methods=['GET'])
def get_judge():
    """读取全局 judge 模型配置。api_key 不回明文，仅返回 has_api_key。"""
    cfg = _read_judge_config()
    return jsonify({
        'api_url': cfg.get('api_url', ''),
        'model_id': cfg.get('model_id', ''),
        'has_api_key': bool(cfg.get('api_key')),
    }), 200


@bp_settings.route('/judge', methods=['POST'])
def save_judge():
    """保存全局 judge 模型配置。

    body: {api_url, model_id, api_key?}。api_key 为空则保留旧值（用户未改 key
    时不清空），便于「只想改 model 不重输 key」的场景。
    """
    data = request.get_json(silent=True) or {}
    api_url = (data.get('api_url') or '').strip()
    model_id = (data.get('model_id') or '').strip()
    api_key = (data.get('api_key') or '').strip()
    if not (api_url and model_id):
        return jsonify({'error': 'api_url 和 model_id 不能为空'}), 400
    old = _read_judge_config()
    new_key = api_key if api_key else old.get('api_key', '')
    _write_judge_config({'api_url': api_url, 'model_id': model_id, 'api_key': new_key})
    logger.info(f'[settings] judge 配置已保存 (api_url={api_url}, model={model_id}, key_保留={not api_key})')
    return jsonify({'status': 'ok', 'has_api_key': bool(new_key)}), 200
