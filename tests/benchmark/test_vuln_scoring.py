"""scoring 内核单测：归一化 / 匹配 / 去重 / 容差 / 指标 / 分桶。

运行：cd evalscope && python -m pytest tests/benchmark/test_vuln_scoring.py -v
"""
from evalscope.benchmarks.vuln_scan.schemas import Finding, GtLocation, GtVuln, Loc
from evalscope.benchmarks.vuln_scan.scoring.matcher import file_match, match
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


# ---- 一 GT 多 finding（重复检出不再计 FP）----
def test_one_to_many_dedup():
    gt = [mk_gt("GT-1", "sql-injection", "a.java", 10)]
    fs = [
        mk_finding("F1", "sqli", "a.java", 10),  # 命中 → TP
        mk_finding("F2", "sql-injection", "a.java", 12),  # 同 GT 重复检出 → 仍 TP
    ]
    r = match(fs, gt)
    assert r.tp == 1  # TP 按去重 GT 数计
    assert r.fp == 0
    assert r.fn == 0
    assert r.classifications == {"F1": "TP", "F2": "TP"}
    assert [m.gt_id for m in r.matches] == ["GT-1", "GT-1"]


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
    fs = [mk_finding("F1", "xss", "jeecg-boot/.../vuln/VulnDemoController.java", 55)]
    assert match(fs, gt).tp == 1


def test_gt_no_line_only_file():
    # GT 不约束行号，只按文件+类型匹配
    gt = [mk_gt("GT-1", "sql-injection", "SysDictController.java")]
    fs = [mk_finding("F1", "sqli", "a/b/SysDictController.java", 300)]
    assert match(fs, gt).tp == 1


# ---- 文件匹配边界（路径分隔符）----
def test_file_match_segment_boundary():
    # 无分隔符边界的不匹配
    assert not file_match("evil.java", "notevil.java")
    assert not file_match("a.java", "xa.java")
    assert not file_match("index.ts", "myindex.ts")
    # 跨目录同名文件不匹配（monorepo）
    assert not file_match("packages/server/src/index.ts", "packages/client/src/index.ts")
    # 合法匹配
    assert file_match("evil.java", "src/evil.java")
    assert file_match("src/evil.java", "repo/src/evil.java")
    assert file_match("VulnDemoController.java", "jeecg-boot/.../VulnDemoController.java")


# ---- 目录级 GT ----
def test_directory_level_gt():
    gt = [mk_gt("GT-1", "xss", "packages/server/src/controllers")]
    fs = [
        mk_finding("F1", "xss", "repo/packages/server/src/controllers/user.ts", 10),  # 目录下 → TP
        mk_finding("F2", "xss", "packages/client/src/controllers/user.ts", 10),  # 目录外 → FP
    ]
    r = match(fs, gt)
    assert (r.tp, r.fp) == (1, 1)
    assert not file_match("packages/server/src/controllers", "xpackages/server/src/controllers/y.ts")


# ---- 空 file GT（无位置约束，仅类型兜底）----
def test_empty_file_gt_matches_by_type():
    gt = [
        mk_gt("GT-1", "ssrf", "pkg/a.ts", 100),  # 精确 GT 优先
        mk_gt("GT-2", "ssrf", ""),  # 无位置约束 → 兜底命中
    ]
    fs = [
        mk_finding("F1", "ssrf", "pkg/a.ts", 100),  # 选 specificity 0 的 GT-1
        mk_finding("F2", "ssrf", "other/b.ts", 5),  # GT-1 位置不符 → 兜底 GT-2
    ]
    r = match(fs, gt)
    assert r.tp == 2
    assert r.fp == 0
    assert {m.gt_id for m in r.matches} == {"GT-1", "GT-2"}


# ---- 确定性：结果与输入顺序无关 ----
def test_order_independence():
    gt = [
        mk_gt("GT-1", "xss", "a.java", 10),
        mk_gt("GT-2", "xss", "a.java", 50),
    ]
    fs = [
        mk_finding("F1", "xss", "a.java", 11),
        mk_finding("F2", "xss", "a.java", 49),
        mk_finding("F3", "xss", "a.java", 9),
    ]
    r1 = match(fs, gt)
    r2 = match(list(reversed(fs)), list(reversed(gt)))
    assert r1.tp == r2.tp and r1.fp == r2.fp
    assert sorted(m.gt_id for m in r1.matches) == sorted(m.gt_id for m in r2.matches)


# ---- 最优 GT 选择：行距近者优先 ----
def test_nearest_gt_preferred():
    gt = [
        mk_gt("GT-1", "xss", "a.java", 100),
        mk_gt("GT-2", "xss", "a.java", 104),
    ]
    fs = [mk_finding("F1", "xss", "a.java", 102)]  # 距 GT-1=2、GT-2=2；tie-break gt_id → GT-1
    r = match(fs, gt)
    assert r.matches[0].gt_id == "GT-1"
    # 行距不等时选近的
    fs2 = [mk_finding("F2", "xss", "a.java", 103)]  # 距 GT-1=3、GT-2=1 → GT-2
    assert match(fs2, gt).matches[0].gt_id == "GT-2"


# ---- B 套（use_type=False，仅位置）----
def test_loc_only_regime():
    gt = [mk_gt("GT-1", "sql-injection", "a.java", 10)]
    # 类型不同但位置吻合：B 套应命中（对照 A 套判 FP）
    fs = [mk_finding("F1", "xss", "src/a.java", 12)]
    assert match(fs, gt).tp == 0
    r = match(fs, gt, use_type=False)
    assert r.tp == 1 and r.matches[0].by == 'location'


# ---- 指标 + 分桶 ----
def test_metrics_and_buckets():
    gt = [
        mk_gt("GT-1", "sql-injection", "a.java", 10),
        mk_gt("GT-2", "xss", "b.java", 20),
        mk_gt("GT-3", "xss", "b.java", 50),
    ]
    fs = [
        mk_finding("F1", "sqli", "a.java", 10),  # TP (sql)
        mk_finding("F2", "xss", "b.java", 20),  # TP (xss, GT-2)
        mk_finding("F3", "xss", "c.java", 99),  # FP (xss, 无 GT)
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
