"""scoring 内核单测：归一化 / 匹配 / 去重 / 容差 / 指标 / 分桶。

运行：cd evalscope && python -m pytest tests/benchmark/test_vuln_scoring.py -v
"""
from evalscope.benchmarks.vuln_scan.schemas import Finding, GtLocation, GtVuln, Loc
from evalscope.benchmarks.vuln_scan.scoring.matcher import match
from evalscope.benchmarks.vuln_scan.scoring.metrics import compute_metrics
from evalscope.benchmarks.vuln_scan.scoring.type_map import normalize


def mk_finding(fid: str, vtype: str, file: str | None = None, line: int | None = None) -> Finding:
    locs = [Loc(file=file, line=line)] if file else []
    return Finding(finding_id=fid, vuln_type=vtype, vuln_type_norm=normalize(vtype), locations=locs)


def mk_gt(gid: str, vtype: str, file: str | None = None, line: int | None = None) -> GtVuln:
    return GtVuln(gt_id=gid, vuln_type=vtype, location=GtLocation(file=file, line=line))


# ---- 归一化 ----
def test_normalize_aliases():
    assert normalize("IDOR") == "idor"
    assert normalize("越权访问") == "broken-access-control"
    assert normalize("SQL Injection") == "sql-injection"
    assert normalize("path_traversal") == "path-traversal"
    assert normalize(None) == "unknown"
    assert normalize("rce") == "command-injection"


# ---- 基本匹配 ----
def test_basic_tp():
    gt = [mk_gt("GT-1", "sql-injection", "a.java", 10)]
    fs = [mk_finding("F1", "sqli", "a.java", 10)]
    r = match(fs, gt)
    assert (r.tp, r.fp, r.fn) == (1, 0, 0)
    assert r.classifications["F1"] == "TP"


def test_fp_and_fn():
    gt = [mk_gt("GT-1", "xss", "a.java", 10)]
    fs = [mk_finding("F1", "sql-injection", "a.java", 10)]  # 类型不符 → FP，GT 漏报
    r = match(fs, gt)
    assert (r.tp, r.fp, r.fn) == (0, 1, 1)


# ---- 一对多去重 ----
def test_one_to_many_dedup():
    gt = [mk_gt("GT-1", "sql-injection", "a.java", 10)]
    fs = [
        mk_finding("F1", "sqli", "a.java", 10),       # 命中 → TP
        mk_finding("F2", "sql-injection", "a.java", 12),  # GT 已命中 → FP
    ]
    r = match(fs, gt)
    assert r.tp == 1                       # 一条 GT 只算一次 TP
    assert r.fp == 1
    assert r.classifications == {"F1": "TP", "F2": "FP"}


# ---- 行容差 ----
def test_line_tolerance_within():
    gt = [mk_gt("GT-1", "xss", "a.java", 100)]
    fs = [mk_finding("F1", "xss", "a.java", 103)]
    assert match(fs, gt, line_tolerance=5).tp == 1


def test_line_tolerance_outside():
    gt = [mk_gt("GT-1", "xss", "a.java", 100)]
    fs = [mk_finding("F1", "xss", "a.java", 103)]
    assert match(fs, gt, line_tolerance=2).tp == 0
    assert match(fs, gt, line_tolerance=2).fp == 1


def test_file_suffix_match():
    # GT 给文件名，finding 给完整路径，应后缀匹配命中
    gt = [mk_gt("GT-1", "xss", "VulnDemoController.java", 55)]
    fs = [mk_finding("F1", "xss",
                     "jeecg-boot/.../vuln/VulnDemoController.java", 55)]
    assert match(fs, gt).tp == 1


def test_gt_no_line_only_file():
    # GT 不约束行号，只按文件+类型匹配
    gt = [mk_gt("GT-1", "sql-injection", "SysDictController.java")]
    fs = [mk_finding("F1", "sqli", "a/b/SysDictController.java", 300)]
    assert match(fs, gt).tp == 1


# ---- 指标 + 分桶 ----
def test_metrics_and_buckets():
    gt = [
        mk_gt("GT-1", "sql-injection", "a.java", 10),
        mk_gt("GT-2", "xss", "b.java", 20),
        mk_gt("GT-3", "xss", "b.java", 50),
    ]
    fs = [
        mk_finding("F1", "sqli", "a.java", 10),    # TP (sql)
        mk_finding("F2", "xss", "b.java", 20),     # TP (xss, GT-2)
        mk_finding("F3", "xss", "c.java", 99),     # FP (xss, 无 GT)
    ]
    r = match(fs, gt)
    snap = compute_metrics(r, fs, gt)
    assert snap.tp == 2
    assert snap.fp == 1
    assert snap.fn == 1
    assert abs(snap.precision - 2 / 3) < 1e-6
    assert abs(snap.recall - 2 / 3) < 1e-6
    assert abs(snap.coverage - 2 / 3) < 1e-6
    # 分桶
    b = {x.vuln_type: x for x in snap.buckets}
    assert b["sql-injection"].tp == 1 and b["sql-injection"].fn == 0
    assert b["xss"].tp == 1 and b["xss"].fn == 1 and b["xss"].fp == 1
