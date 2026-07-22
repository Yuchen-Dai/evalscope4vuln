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

    # ---- 按 vuln_type 分桶 ----
    finding_by_id = {f.finding_id: f for f in findings}
    found_gt_ids = {m.gt_id for m in match_result.matches}

    f_fp: dict[str, int] = defaultdict(int)
    for fid, cls in match_result.classifications.items():
        f = finding_by_id.get(fid)
        if not f:
            continue
        if cls == "FP":
            f_fp[f.vuln_type_norm] += 1

    g_total: dict[str, int] = defaultdict(int)
    g_found: dict[str, int] = defaultdict(int)
    for g in gt:
        t = normalize(g.vuln_type)
        g_total[t] += 1
        if g.gt_id in found_gt_ids:
            g_found[t] += 1

    all_types = set(g_total) | set(f_fp)
    buckets: list[Bucket] = []
    for t in sorted(all_types):
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

    return MetricsSnapshot(
        tp=tp, fp=fp, fn=fn,
        precision=precision, recall=recall, coverage=coverage, f1=f1,
        buckets=buckets,
        findings_total=len(findings), gt_total=len(gt),
    )
