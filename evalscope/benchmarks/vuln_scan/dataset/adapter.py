"""GT 文件加载适配器。

支持 YAML / JSON。相对路径以 vulnbench/ 根目录为基准（即本仓库 vulnbench/）。
"""
from __future__ import annotations

import json
import os

import yaml

from evalscope.benchmarks.vuln_scan.schemas import GroundTruth

# vulnbench/ 根目录（adapter.py 位于 vulnbench/dataset/ 下）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve(path: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.join(_ROOT, path)


def load_gt(path: str) -> GroundTruth:
    """读取 GT 文件并校验为 GroundTruth 模型。"""
    full = _resolve(path)
    with open(full, encoding="utf-8") as f:
        text = f.read()
    if full.endswith((".yaml", ".yml")):
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"GT 文件 {path} 顶层必须是 mapping")
    return GroundTruth.model_validate(data)
