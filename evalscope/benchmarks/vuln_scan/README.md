# Vuln-Scan Benchmark — 漏洞挖掘测评

基于图灵平台对目标工程做静态漏洞扫描，将扫描结果与 Ground Truth 比对，算出 TP/FP/FN、Precision/Recall/Coverage/F1，按漏洞类型分桶。

## 架构

```
benchmarks/vuln_scan/
├── adapter.py              # 通用 VulnBenchmarkAdapter（run_inference + match_score）
├── registry_adapter.py     # 扫描 datasets/ 动态注册每个数据集为 vuln_<name> benchmark
├── config.py               # 配置（轮询间隔/超时等）
├── schemas.py              # 数据模型（Finding/GT/Score/ScanConfig）
├── turing/client.py        # 图灵平台 HTTP client（唯一对接缝，trust_env=False）
├── scoring/
│   ├── matcher.py          # GT 匹配内核（位置+类型，TP/FP/FN，一对多去重）
│   ├── metrics.py          # Precision/Recall/Coverage/F1 + 按 vuln_type 分桶
│   └── type_map.py         # vuln_type 归一化映射表（中英噪声→规范类型）
├── dataset/
│   ├── adapter.py          # GT 文件加载（load_gt）
│   └── gt_schema.py        # GT pydantic schema
├── datasets/               # 每个漏洞数据集一个目录
│   ├── jeecgboot/
│   │   ├── default_test.jsonl   # scan_config（platform/detect_types 全选）+ GT 路径
│   │   └── gt.yaml              # Ground Truth
│   └── flowise/                 # （占位，后续接真实图灵平台补 GT）
└── tests/
    └── test_vuln_scoring.py     # scorer 单测（9 用例）
```

## benchmark 自带属性 vs 运行时参数

| 属性 | 来源 | 说明 |
|---|---|---|
| platform | benchmark dataset | 按工程类型（jeecgboot/flowise → web） |
| detect_types | benchmark dataset | 全选该 platform 下全部探测类型 |
| GT (gt.yaml) | benchmark dataset | 每个数据集的漏洞标注 |
| project_name | **Tasks 页用户填** | 图灵不允许重名，每次提交唯一 |
| model_name | Tasks 页用户填 | 扫描用模型（不填则 default） |
| max_concurrency / priority / 超时 | Tasks 页用户填 | 扫描参数 |

## 加新数据集

在 `datasets/` 下建一个目录（含 `default_test.jsonl` + `gt.yaml`），重启 service 后自动注册为 `vuln_<目录名>` benchmark，出现在 Benchmarks 页。

### default_test.jsonl 格式
```json
{"input":"Scan target: <name>","target":"","metadata":{"scan_config":{"platforms":"web","detect_types":"<全选 value 逗号拼接>","priority":"100","turing_base_url":"http://127.0.0.1:8088","timeout":120}}}
```

### gt.yaml 格式
```yaml
target: <目标名>
vulnerabilities:
  - gt_id: GT-001
    vuln_type: path-traversal      # 归一化类型
    severity: HIGH
    location:
      file: VulnDemoController.java  # 后缀匹配
      line: 55                       # 行容差 ±5
```

## 评估机制

1. **run_inference**：调图灵 create_project → submit_scan → 指数退避轮询（初始 5s ×1.5 上限 120s，有新 finding 重置）→ get_report_data 拿 findings
2. **match_score**：findings ↔ GT 按类型(归一化)+位置(文件后缀+行容差)匹配 → TP/FP/FN（一对多去重）
3. **指标**：Precision/Recall/Coverage/F1 + 按 vuln_type 分桶 → Score.value → evalscope Report

## 轮询日志（前端 LogViewer 实时展示）

```
[vuln_scan] → POST /projects/local  display_name="xxx" local_path="..."
[vuln_scan] ← project_id=xxx
[vuln_scan] → POST /scan  platforms=web detect_types=22项 model_name=glm-5.1 ...
[vuln_scan] ← job_id=xxx
[vuln_scan] 第2轮（间隔5s）: 已发现 222 个漏洞（状态: running）
[vuln_scan] 任务完成，共轮询 3 轮
[vuln_scan] ← 获取完成: 442 个 finding
```

## 真实图灵平台对接

只需改 `turing/client.py`（唯一对接缝）。注意：
- 真实图灵需要鉴权（JWT Cookie `turing_session`），当前 mock 无需——需加 login 方法
- 真实图灵 `POST /scan` 返 303 Redirect（mock 返 JSON）
