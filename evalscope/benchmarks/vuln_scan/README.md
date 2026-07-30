# Vuln-Scan Benchmark — 漏洞挖掘测评

基于图灵平台对目标工程做静态漏洞扫描，将扫描结果与 Ground Truth 比对，算出 TP/FP/FN、Precision/Recall/Coverage/F1，按漏洞类型分桶。

## 架构

```
benchmarks/vuln_scan/
├── adapter.py              # 通用 VulnBenchmarkAdapter（run_inference + match_score）
├── registry_adapter.py     # 扫描 datasets/ 动态注册每个数据集为 vuln_<name> benchmark
├── config.py               # 配置（base_url/鉴权账号/轮询间隔/超时等）
├── schemas.py              # 数据模型（Finding/GT/Score/ScanConfig）
├── turing/client.py        # 图灵平台 HTTP client（唯一对接缝，trust_env=False；login 鉴权 + upload 上传）
├── scoring/
│   ├── matcher.py          # GT 匹配内核（位置+类型，TP/FP/FN，一对多去重）
│   ├── metrics.py          # Precision/Recall/Coverage/F1 + 按 vuln_type 分桶
│   └── type_map.py         # vuln_type 归一化映射表（中英噪声→规范类型）
├── dataset/
│   ├── adapter.py          # GT 文件加载（load_gt）
│   └── gt_schema.py        # GT pydantic schema
├── datasets/               # 每个漏洞数据集一个目录
│   ├── jeecgboot/
│   │   ├── default_test.jsonl   # scan_config（platform/detect_types 全选）+ source_path
│   │   ├── gt.yaml              # Ground Truth
│   │   └── jeecgboot.zip        # 上传给图灵的源码包（占位，需替换真实 JeecgBoot 源码）
│   └── flowise/
│       ├── default_test.jsonl
│       ├── gt.yaml
│       └── flowise.zip          # flowise 源码包（已含）
└── tests/
```

## benchmark 自带属性 vs 运行时参数

| 属性 | 来源 | 说明 |
|---|---|---|
| platform | benchmark dataset | 按工程类型（jeecgboot/flowise → web） |
| detect_types | benchmark dataset | 全选该 platform 下全部探测类型 |
| GT (gt.yaml) | benchmark dataset | 每个数据集的漏洞标注 |
| source_path | benchmark dataset | 上传给图灵的源码 zip（相对 dataset 目录或绝对路径） |
| project_name | **Tasks 页用户填** | 图灵不允许重名，每次提交唯一 |
| model_name | Tasks 页用户填 | 扫描用模型（不填则 default） |
| max_concurrency / priority / 超时 | Tasks 页用户填 | 扫描参数 |

## 加新数据集

在 `datasets/` 下建一个目录（含 `default_test.jsonl` + `gt.yaml` + 源码 zip），重启 service 后自动注册为 `vuln_<目录名>` benchmark，出现在 Benchmarks 页。

### default_test.jsonl 格式
```json
{"input":"Scan target: <name>","target":"","metadata":{"scan_config":{"source_path":"<name>.zip","platforms":"web","detect_types":"<全选 value 逗号拼接>","priority":"100","turing_base_url":"http://127.0.0.1:8088","timeout":120}}}
```
`source_path`：上传给图灵的源码 zip。相对 dataset 目录（adapter 解析为绝对，部署无关）或绝对路径。每个 dataset 需准备对应源码 zip（见下「源码 zip 准备」）。

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

1. **run_inference**：调图灵 `login` 鉴权 → `upload_project`（上传源码 zip，multipart `file`+`version`）→ `submit_scan` → 指数退避轮询（初始 5s ×1.5 上限 120s，有新 finding 重置）→ `get_report_data` 拿 findings
2. **match_score**：findings ↔ GT 按类型(归一化)+位置(文件后缀+行容差)匹配 → TP/FP/FN（一对多去重）
3. **指标**：Precision/Recall/Coverage/F1 + 按 vuln_type 分桶 → Score.value → evalscope Report

## 轮询日志（前端 LogViewer 实时展示）

```
[vuln_scan] 登录图灵（http://127.0.0.1:8088 用户=admin）
[vuln_scan] → POST /projects/upload  display_name="<project_name>" filename="jeecgboot" source=".../jeecgboot.zip" version="1.0.0"
[vuln_scan] ← project_id=xxx
[vuln_scan] → POST /scan  platforms=web detect_types=22项 model_name=glm-5.1 ...
[vuln_scan] ← job_id=xxx
[vuln_scan] 第2轮（间隔5s）: 已发现 222 个漏洞（状态: running）
[vuln_scan] 任务完成，共轮询 3 轮
[vuln_scan] ← 获取完成: 442 个 finding
```

## 真实图灵平台对接

`config.py` 配 base_url + 鉴权账号，`turing/client.py` 是唯一对接缝。已实现：
- **鉴权**：`login`（POST /api/auth/login，`admin`/`admin123` 默认；环境变量 `TURING_USERNAME`/`TURING_PASSWORD` 覆盖；httpx cookie jar 自动带 `turing_session`）。注意环境变量须在 service **启动时**设置（config.py 仅启动时读一次）。
- **建项目**：`upload_project`（POST /api/projects/upload，multipart：文件字段 `name=file`/`filename=<源码文件名>`，外加 `display_name`+`version`）。`display_name` = project_name（用户每次填的唯一名），**重复判断依据 display_name+version**，故同 dataset 不同 project_name 不会重复；409 即项目已存在，按规则中断。真实图灵是 server-side 扫描，代码经上传交付，不再用 `/projects/local`（其 `local_path` 在图灵服务器不存在会 400）。

待办（真实平台确认后改 client.py）：
- 真实图灵 `POST /scan` 返 303 Redirect（mock 返 JSON），`submit_scan` 需处理重定向。

## 源码 zip 准备

每个 dataset 需一个源码 zip（`source_path` 指向），上传给图灵做 server-side 扫描：
- **flowise**：已含 `flowise.zip`（来自 `vuln_dataset/flowise_vulngym` 源码，1948 文件）。
- **jeecgboot**：仓库内无 JeecgBoot 源码，`jeecgboot.zip` 为占位（仅 gt.yaml + jsonl）——替换为真实 JeecgBoot 源码 zip 后即可。

打包：把目标工程源码打成 zip（排除 `node_modules`/`.git`/`dist` 等），放 dataset 目录，`source_path` 填 `<name>.zip`（相对 dataset 目录，adapter 自动解析为绝对路径）。
