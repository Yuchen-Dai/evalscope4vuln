"""GT 匹配内核（VulnMatcher）。

纯函数：给定一组 finding 与一组 GT，按「类型(归一化) + 位置(路径段 + 行容差)」
配对，产出 TP/FP/FN。一条 GT 可匹配多条 finding（同一漏洞多路上报都算 TP），
TP 计数按去重 GT 数；只有不匹配任何 GT 的 finding 才计 FP。

配对确定性：每条 finding 独立选取「最优」GT（排序键 = 路径精确度、行距离、
gt_id 字典序），与 findings/GT 的输入顺序无关，同输入必得同结果。

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


def _file_specificity(gt_file: str | None, finding_file: str | None) -> int | None:
    """文件匹配的精确度：None=不匹配；数值越小越精确。

    0 = GT 是文件名/文件路径，命中 finding 路径末段（含完全相等）
    1 = GT 是目录，finding 位于该目录下（容忍缺 repo 根前缀）
    2 = GT 不约束文件（None/空串），仅靠类型+行匹配

    所有规则都带路径分隔符边界：GT `evil.java` 不匹配 `notevil.java`，
    GT `a.java` 不匹配 `xa.java`，跨目录同名文件不匹配（monorepo 场景）。
    """
    if not gt_file:
        return 2
    if not finding_file:
        return None
    g = _norm_path(gt_file)
    f = _norm_path(finding_file)
    if not g or not f:
        return None
    if f == g or f.endswith('/' + g):
        return 0
    if f.startswith(g + '/') or ('/' + g + '/') in f:
        return 1
    return None


def file_match(gt_file: str | None, finding_file: str | None) -> bool:
    """文件匹配（兼容入口）：GT 与 finding 的文件约束可配对。"""
    return _file_specificity(gt_file, finding_file) is not None


def _has_line_constraint(gt: GtLocation) -> bool:
    return gt.line is not None or bool(gt.line_range)


def line_match(gt: GtLocation, finding_line: int | None, tol: int) -> bool:
    """行匹配。GT 未给行约束时视为通过（只靠文件+类型）。"""
    if not _has_line_constraint(gt):
        return True
    if finding_line is None:
        return False
    if gt.line_range and len(gt.line_range) == 2:
        lo, hi = gt.line_range
        return (lo - tol) <= finding_line <= (hi + tol)
    if gt.line is not None:
        return abs(finding_line - gt.line) <= tol
    return True


def _line_distance(gt: GtLocation, finding_line: int | None, tol: int) -> int:
    """排序用行距离：无行约束/无行号 = tol+1（比任何行级命中都泛）。"""
    if not _has_line_constraint(gt) or finding_line is None:
        return tol + 1
    if gt.line_range and len(gt.line_range) == 2:
        lo, hi = gt.line_range
        if lo <= finding_line <= hi:
            return 0
        return min(abs(finding_line - lo), abs(finding_line - hi))
    return abs(finding_line - gt.line)


def _pair_key(gt: GtVuln, finding: Finding, tol: int) -> tuple[int, int] | None:
    """finding↔GT 可行配对的排序键；None = 不可匹配（取最优 loc）。"""
    if not finding.locations:
        # finding 无位置：仅当 GT 既不约束文件也不约束行时，靠类型匹配
        if gt.location.file or _has_line_constraint(gt.location):
            return None
        return (2, tol + 1)
    best: tuple[int, int] | None = None
    for loc in finding.locations:
        specificity = _file_specificity(gt.location.file, loc.file)
        if specificity is None:
            continue
        if not line_match(gt.location, loc.line, tol):
            continue
        key = (specificity, _line_distance(gt.location, loc.line, tol))
        if best is None or key < best:
            best = key
    return best


def match(
    findings: list[Finding], gt: list[GtVuln], line_tolerance: int | None = None, use_type: bool = True
) -> MatchResult:
    """对全量 findings 与 GT 做匹配（无状态，每轮可重算）。

    每条 finding 独立选取最优 GT（一 GT 可匹配多 finding，重复检出均为 TP，
    不再计 FP）；TP 按去重 GT 数计。结果与输入顺序无关（排序键含 gt_id tie-break）。

    Returns:
        MatchResult: tp=命中GT数(去重), fp=未命中finding数, fn=未命中GT数
    """
    tol = config.LINE_TOLERANCE if line_tolerance is None else line_tolerance
    result = MatchResult()

    for f in findings:
        best_key: tuple[int, int, str] | None = None
        best_gt: GtVuln | None = None
        for g in gt:
            if use_type and f.vuln_type_norm != normalize(g.vuln_type):
                continue
            key = _pair_key(g, f, tol)
            if key is None:
                continue
            ranked = (key[0], key[1], g.gt_id)
            if best_key is None or ranked < best_key:
                best_key, best_gt = ranked, g
        if best_gt is not None:
            result.matches.append(
                Match(finding_id=f.finding_id, gt_id=best_gt.gt_id, by='type+location' if use_type else 'location')
            )
            result.classifications[f.finding_id] = "TP"
        else:
            result.unmatched_findings.append(f.finding_id)
            result.classifications[f.finding_id] = "FP"

    hit_gt: set[str] = {m.gt_id for m in result.matches}
    result.missed_gt = [g.gt_id for g in gt if g.gt_id not in hit_gt]

    result.tp = len(hit_gt)
    result.fp = len(result.unmatched_findings)
    result.fn = len(result.missed_gt)
    return result
