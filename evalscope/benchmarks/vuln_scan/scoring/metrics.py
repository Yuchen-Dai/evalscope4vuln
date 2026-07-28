"""指标计算：Precision/Recall/Coverage/F1 + 按 vuln_type 分桶。

定义：
- Precision = TP / (TP + FP)
- Recall    = TP / (TP + FN)
- Coverage  = 命中 GT 数 / GT 总数  （数值上 = Recall，强调"GT 覆盖率"语义）
- F1        = 2PR / (P + R)
- TP 取「被命中的 GT 数」（一对多去重）；FN 为漏报 GT；FP 为误报 finding。
"""
from __future__ import annotations

from collections import defaultdict

from evalscope.benchmarks.vuln_scan.schemas import Bucket, Finding, GtVuln, MatchResult, MetricsSnapshot
from evalscope.benchmarks.vuln_scan.scoring.type_map import normalize


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def compute_metrics(match_result: MatchResult,
                    findings: list[Finding],
                    gt: list[GtVuln]) -> MetricsSnapshot:
    tp, fp, fn = match_result.tp, match_result.fp, match_result.fn
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    coverage = _safe_div(tp, len(gt))   # = recall
    f1 = _safe_div(2 * precision * recall, precision + recall)

    # ---- 按 vuln_type 分桶（仅 GT 类型 + 一个 other-fp 汇总桶）----
    # 分桶维度用 GT 类型（评估本质是对 GT 的覆盖）。未命中任何 GT 类型的 FP
    # finding——图灵返回的自由文本类型可能数百种——统一汇总进 other-fp，
    # 避免子集分数随误报类型爆炸。
    finding_by_id = {f.finding_id: f for f in findings}
    found_gt_ids = {m.gt_id for m in match_result.matches}

    gt_types: dict[str, None] = {}              # 保序：GT 出现的归一化类型
    for g in gt:
        gt_types.setdefault(normalize(g.vuln_type), None)

    f_fp: dict[str, int] = defaultdict(int)     # 仅属于某 GT 类型桶的 FP 计数
    other_fp = 0
    for fid, cls in match_result.classifications.items():
        f = finding_by_id.get(fid)
        if not f or cls != "FP":
            continue
        if f.vuln_type_norm in gt_types:
            f_fp[f.vuln_type_norm] += 1
        else:
            other_fp += 1

    g_total: dict[str, int] = defaultdict(int)
    g_found: dict[str, int] = defaultdict(int)
    for g in gt:
        t = normalize(g.vuln_type)
        g_total[t] += 1
        if g.gt_id in found_gt_ids:
            g_found[t] += 1

    buckets: list[Bucket] = []
    for t in gt_types:                          # 按 GT 类型（保序）
        b_tp = g_found[t]                       # 该类型命中 GT 数
        b_fp = f_fp[t]                          # 该类型误报 finding 数
        b_fn = g_total[t] - g_found[t]
        b_p = _safe_div(b_tp, b_tp + b_fp)
        b_r = _safe_div(b_tp, b_tp + b_fn)
        b_f1 = _safe_div(2 * b_p * b_r, b_p + b_r)
        buckets.append(Bucket(
            vuln_type=t, tp=b_tp, fp=b_fp, fn=b_fn,
            precision=b_p, recall=b_r, f1=b_f1,
            gt_total=g_total[t], found=g_found[t],
        ))

    if other_fp > 0:
        # 未命中任何 GT 类型的误报汇总：无对应 GT，故 TP/FN/Recall=0、Precision=0。
        buckets.append(Bucket(
            vuln_type="other-fp", tp=0, fp=other_fp, fn=0,
            precision=0.0, recall=0.0, f1=0.0,
            gt_total=0, found=0,
        ))

    return MetricsSnapshot(
        tp=tp, fp=fp, fn=fn,
        precision=precision, recall=recall, coverage=coverage, f1=f1,
        buckets=buckets,
        findings_total=len(findings), gt_total=len(gt),
    )
