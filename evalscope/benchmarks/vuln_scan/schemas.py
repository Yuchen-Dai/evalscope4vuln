"""vulnbench 数据模型（pydantic v2）。

涵盖：扫描配置、规范化 Finding、Ground Truth、匹配结果、指标快照、Run 记录。
图灵平台返回的原始 finding dict 由 turing/client.py 解析为 Finding。
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ===== 位置与 Finding =====

class Loc(BaseModel):
    """finding 的一个代码位置（从 source/sink/call_chain 提取）。"""
    file: Optional[str] = None
    line: Optional[int] = None
    function: Optional[str] = None


class Finding(BaseModel):
    """规范化的漏洞发现结果（供 matcher 使用）。"""
    finding_id: str
    display_id: Optional[str] = None
    vuln_type: str                       # 原始类型
    vuln_type_norm: str                  # 归一化后类型（经 type_map）
    severity: str = "MEDIUM"             # 归一化大写
    confidence: int = 0
    validation_result: Optional[str] = None
    title: Optional[str] = None
    locations: list[Loc] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)   # 原始字段，报告/调试用


# ===== Ground Truth =====

class GtLocation(BaseModel):
    file: Optional[str] = None
    line: Optional[int] = None
    line_range: Optional[list[int]] = None   # [start, end] 闭区间
    function: Optional[str] = None


class GtVuln(BaseModel):
    gt_id: str
    vuln_type: str                  # 用户在 GT 中写归一化类型（adapter 也会再归一化一次）
    cwe: Optional[str] = None
    severity: Optional[str] = None
    location: GtLocation
    description: Optional[str] = None


class GroundTruth(BaseModel):
    target: str
    project_id: Optional[str] = None
    vulnerabilities: list[GtVuln] = Field(default_factory=list)


# ===== 匹配结果与指标 =====

class Match(BaseModel):
    finding_id: str
    gt_id: str
    by: str = "type+location"


class MatchResult(BaseModel):
    tp: int = 0
    fp: int = 0
    fn: int = 0
    matches: list[Match] = Field(default_factory=list)
    unmatched_findings: list[str] = Field(default_factory=list)   # finding_id
    missed_gt: list[str] = Field(default_factory=list)            # gt_id
    classifications: dict[str, str] = Field(default_factory=dict)  # finding_id -> "TP"/"FP"


class Bucket(BaseModel):
    vuln_type: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    gt_total: int = 0
    found: int = 0


class MetricsSnapshot(BaseModel):
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    coverage: float = 0.0
    f1: float = 0.0
    buckets: list[Bucket] = Field(default_factory=list)
    findings_total: int = 0
    gt_total: int = 0


# ===== 扫描配置与 Run =====

class ScanConfig(BaseModel):
    """配置驱动的扫描参数（对应流程第 2 步的 6 个字段）。"""
    display_name: str = "vulnbench-target"
    source_path: str = ""                  # 源码压缩包绝对路径（上传给图灵，server-side 扫描）
    platforms: str = "web"                 # 逗号分隔，对应图灵 platforms
    detect_types: str = ""                 # 逗号分隔，用 detect-types 的 value
    priority: str = "100"
    model_name: str = ""
    max_concurrency: str = ""
    phase1_timeout: str = ""
    phase2_timeout: str = ""
    phase3_timeout: str = ""
    gt_file: str = "gt/jeecgboot.yaml"     # 本次评测用的 GT 文件（相对 vulnbench/ 或绝对路径）


class Run(BaseModel):
    run_id: str
    project_id: Optional[str] = None
    job_id: Optional[str] = None
    target: str = ""
    config: ScanConfig
    status: str = "pending"                # pending/running/completed/failed
    created_at: str = ""
    completed_at: Optional[str] = None
    error: Optional[str] = None
