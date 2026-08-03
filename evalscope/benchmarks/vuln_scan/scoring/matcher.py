"""GT 匹配内核（VulnMatcher）。

纯函数：给定一组 finding 与一组 GT，按「类型(归一化) + 位置(文件后缀 + 行容差/函数)」
配对，产出 TP/FP/FN。一条 GT 被多条 finding 命中时只算一次 TP（多余 finding 计 FP）。

实时仪表盘（轮询中）与 Inspect scorer（run 结束）共享本内核，逻辑只此一份。
"""
from __future__ import annotations

import os

from evalscope.benchmarks.vuln_scan import config
from evalscope.benchmarks.vuln_scan.schemas import Finding, GtLocation, GtVuln, Match, MatchResult
from evalscope.benchmarks.vuln_scan.scoring.type_map import normalize


def _norm_path(p: str | None) -> str:
    if not p:
        return ""
    return p.replace("\\", "/").lower().strip()


def file_match(gt_file: str | None, finding_file: str | None) -> bool:
    """文件匹配：GT 给的 file（可能是文件名或部分路径）作为 finding 完整路径的后缀/包含。"""
    if not gt_file or not finding_file:
        return False
    g = _norm_path(gt_file)
    f = _norm_path(finding_file)
    if not g or not f:
        return False
    if f.endswith(g):
        return True
    if g in f:
        return True
    g_base, f_base = os.path.basename(g), os.path.basename(f)
    if g_base and f_base and g_base == f_base:
        return True
    return False


def line_match(gt: GtLocation, finding_line: int | None, tol: int) -> bool:
    """行匹配。GT 未给行约束时视为通过（只靠文件+类型）。"""
    has_constraint = gt.line is not None or bool(gt.line_range)
    if not has_constraint:
        return True
    if finding_line is None:
        return False
    if gt.line_range and len(gt.line_range) == 2:
        lo, hi = gt.line_range
        return (lo - tol) <= finding_line <= (hi + tol)
    if gt.line is not None:
        return abs(finding_line - gt.line) <= tol
    return True


def _loc_match(gt: GtVuln, finding: Finding, tol: int) -> bool:
    """finding 任一 location 与 GT.location 的文件+行同时匹配。"""
    if not finding.locations:
        # finding 无位置：仅当 GT 也不约束文件时，靠类型匹配
        return gt.location.file is None
    for loc in finding.locations:
        if not file_match(gt.location.file, loc.file):
            continue
        if line_match(gt.location, loc.line, tol):
            return True
    return False


def match(findings: list[Finding],
          gt: list[GtVuln],
          line_tolerance: int | None = None,
          use_type: bool = True) -> MatchResult:
    """对全量 findings 与 GT 做匹配（无状态，每轮可重算）。

    Returns:
        MatchResult: tp=命中GT数(去重), fp=未命中finding数, fn=未命中GT数
    """
    tol = config.LINE_TOLERANCE if line_tolerance is None else line_tolerance
    result = MatchResult()
    found_gt: set[str] = set()

    for f in findings:
        matched_gt_id: str | None = None
        for g in gt:
            if g.gt_id in found_gt:
                continue
            if use_type and f.vuln_type_norm != normalize(g.vuln_type):
                continue
            if _loc_match(g, f, tol):
                matched_gt_id = g.gt_id
                break
        if matched_gt_id:
            found_gt.add(matched_gt_id)
            result.matches.append(Match(finding_id=f.finding_id, gt_id=matched_gt_id,
                                        by='type+location' if use_type else 'location'))
            result.classifications[f.finding_id] = "TP"
        else:
            result.unmatched_findings.append(f.finding_id)
            result.classifications[f.finding_id] = "FP"

    for g in gt:
        if g.gt_id not in found_gt:
            result.missed_gt.append(g.gt_id)

    result.tp = len(found_gt)
    result.fp = len(result.unmatched_findings)
    result.fn = len(result.missed_gt)
    return result
