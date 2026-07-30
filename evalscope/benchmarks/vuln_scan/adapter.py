# Copyright (c) Alibaba, Inc. and its affiliates.
# Vuln-Scan 通用 adapter：对接图灵平台做漏洞挖掘测评。
# 本文件只定义通用类；每个数据集由 registry_adapter.py 扫描 datasets/ 动态注册成 benchmark。
import asyncio
import json
import os
import time
from typing import Any, Dict, List

from evalscope.api.benchmark import DefaultDataAdapter
from evalscope.api.dataset import Sample
from evalscope.api.evaluator import TaskState
from evalscope.api.messages import ChatMessageUser
from evalscope.api.metric import Score
from evalscope.api.model import Model, ModelOutput
from evalscope.utils.logger import get_logger

from evalscope.benchmarks.vuln_scan import config as vb_config
from evalscope.benchmarks.vuln_scan.turing.client import TuringClient, parse_findings
from evalscope.benchmarks.vuln_scan.scoring.matcher import match as do_match
from evalscope.benchmarks.vuln_scan.scoring.metrics import compute_metrics
from evalscope.benchmarks.vuln_scan.dataset.adapter import load_gt
from evalscope.benchmarks.vuln_scan.schemas import ScanConfig

logger = get_logger()


def _run_async(coro):
    """在同步 run_inference 中跑 async TuringClient（evalscope 用线程池调用 run_inference）。"""
    try:
        asyncio.get_running_loop()       # 已在 loop 内（罕见）→ 新线程跑
        import threading
        box = [None]

        def _r():
            box[0] = asyncio.run(coro)
        t = threading.Thread(target=_r)
        t.start()
        t.join()
        return box[0]
    except RuntimeError:
        return asyncio.run(coro)


def _build_scan_config(scan_cfg: Dict[str, Any]) -> ScanConfig:
    return ScanConfig(
        display_name=scan_cfg.get('display_name', 'vulnbench-target'),
        source_path=scan_cfg.get('source_path', ''),
        platforms=scan_cfg.get('platforms', 'web'),
        detect_types=scan_cfg.get('detect_types', ''),
        priority=str(scan_cfg.get('priority', '100')),
        model_name=scan_cfg.get('model_name', ''),
        max_concurrency=str(scan_cfg.get('max_concurrency', '')),
        phase1_timeout=str(scan_cfg.get('phase1_timeout', '')),
        phase2_timeout=str(scan_cfg.get('phase2_timeout', '')),
        phase3_timeout=str(scan_cfg.get('phase3_timeout', '')),
    )


async def _scan_async(scan_cfg: Dict[str, Any], project_name: str, model_name: str = '', dataset_name: str = '') -> List[Dict[str, Any]]:
    """提交图灵扫描 → 轮询到完成 → 返回完整 finding 列表（原始 dict）。

    轮询采用指数退避（初始 5s，每轮 ×1.5，上限 120s），适配数小时的长任务。
    每轮调 report-overview 拉增量 finding 数，记到日志（前端 LogViewer 实时展示）。
    project_name 来自 benchmark dataset，映射到图灵 create_project 的 display_name。
    model_name 从前端 scan_config 透传（用于日志展示 + 图灵 submit_scan）。
    """
    base_url = scan_cfg.get('turing_base_url') or vb_config.TURING_BASE_URL
    client = TuringClient(base_url=base_url)
    try:
        # 鉴权（fake_turing 不校验；正式平台 set-cookie turing_session，httpx cookie jar 后续自动带）
        await client.login(vb_config.TURING_USERNAME, vb_config.TURING_PASSWORD)
        logger.info(f'[vuln_scan] 登录图灵（{base_url} 用户={vb_config.TURING_USERNAME}）')
        sc = _build_scan_config(scan_cfg)
        # 上传源码创建项目（真实图灵 server-side 扫描，代码经上传交付；local_path 在服务器不存在会 400）
        logger.info(f'[vuln_scan] → POST /projects/upload  filename="{dataset_name}" source="{sc.source_path}" version="1.0.0"')
        try:
            pid = await client.upload_project(dataset_name, sc.source_path)
        except Exception as e:
            if getattr(getattr(e, 'response', None), 'status_code', None) == 409:
                logger.error(f'[vuln_scan] 项目 "{dataset_name}" 已存在（409 重复上传），按规则中断执行')
            raise
        logger.info(f'[vuln_scan] ← project_id={pid}')
        # 提交扫描
        logger.info(f'[vuln_scan] → POST /scan  platforms={sc.platforms} '
                    f'detect_types={len(sc.detect_types.split(",")) if sc.detect_types else 0}项 '
                    f'priority={sc.priority} model_name={model_name or "(默认)"} '
                    f'max_concurrency={sc.max_concurrency or "(默认)"} '
                    f'phase_timeout=({sc.phase1_timeout or "-"}/{sc.phase2_timeout or "-"}/{sc.phase3_timeout or "-"})')
        job_id = await client.submit_scan(pid, sc)
        logger.info(f'[vuln_scan] ← job_id={job_id}')
        logger.info(f'[vuln_scan] 开始轮询（指数退避: 初始 5s, 上限 120s, 图灵: {base_url}）')
        deadline = time.time() + float(scan_cfg.get('timeout', vb_config.POLL_TIMEOUT))
        interval = 5.0       # 初始轮询间隔
        max_interval = 120.0  # 上限（避免退避太久）
        poll_count = 0
        prev_finding_count = -1
        while True:
            poll_count += 1
            await asyncio.sleep(interval)
            try:
                st = await client.get_status(pid, job_id)
            except Exception as e:
                logger.warning(f'[vuln_scan] 第{poll_count}轮状态查询失败（间隔{interval:.0f}s）: {e}')
                if time.time() > deadline:
                    break
                interval = min(interval * 1.5, max_interval)
                continue
            # 每轮拉 report-overview 看增量 finding（写日志，前端 LogViewer 实时展示）
            try:
                overview = await client.get_report_overview(pid, job_id)
                cur_findings = overview.get('findings') or []
                cur_count = len(cur_findings)
                status_str = st.get('status', '?')
                if cur_count != prev_finding_count:
                    # finding 数有变化（新增）→ 重置退避（可能正在密集产出）
                    logger.info(f'[vuln_scan] 第{poll_count}轮（间隔{interval:.0f}s）: '
                                f'已发现 {cur_count} 个漏洞（状态: {status_str}）')
                    prev_finding_count = cur_count
                    interval = 5.0   # 有新 finding → 重置为初始间隔（密集期）
                else:
                    logger.info(f'[vuln_scan] 第{poll_count}轮（间隔{interval:.0f}s）: '
                                f'已发现 {cur_count} 个漏洞，无新增（状态: {status_str}）')
                    interval = min(interval * 1.5, max_interval)
            except Exception:
                logger.info(f'[vuln_scan] 第{poll_count}轮（间隔{interval:.0f}s）: 扫描中（状态: {st.get("status", "?")}）')
                interval = min(interval * 1.5, max_interval)
            if st.get('status') == 'completed':
                logger.info(f'[vuln_scan] 任务完成，共轮询 {poll_count} 轮')
                break
            if time.time() > deadline:
                logger.warning(f'[vuln_scan] 轮询超时（{poll_count}轮），取当前结果')
                break
        logger.info(f'[vuln_scan] → GET /report-data  project={pid} job={job_id}')
        data = await client.get_report_data(pid, job_id)
        findings = data.get('findings') or []
        logger.info(f'[vuln_scan] ← 获取完成: {len(findings)} 个 finding')
        return findings
    finally:
        logger.info('[vuln_scan] 关闭图灵连接')
        await client.aclose()


class VulnBenchmarkAdapter(DefaultDataAdapter):
    """通用漏洞挖掘测评 adapter。每个数据集由 registry_adapter.py 注册成一个 benchmark。"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_aggregation_name = False   # 报告 metric_name 不带 mean_ 前缀

    # 本地 jsonl 加载（强制 LocalDataLoader）
    def load_from_disk(self, **kwargs):
        return super().load_from_disk(use_local_loader=True)

    @staticmethod
    def _load_scan_config(task_config) -> Dict[str, Any]:
        """从 work_dir/scan_config.json 读表单 scan_config（eval.py 写入）。

        不能走 dataset_args[name]：加载 benchmark 时 BenchmarkMeta._update 会过滤掉
        scan_config 这种非 meta 字段，导致表单填的 turing_base_url 等全部丢失。
        """
        work_dir = getattr(task_config, 'work_dir', '') or ''
        try:
            with open(os.path.join(work_dir, 'scan_config.json'), encoding='utf-8') as f:
                return json.load(f) or {}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    # record → Sample：扫描配置与 GT 路径都放 metadata
    def record_to_sample(self, record: Dict[str, Any]) -> Sample:
        meta = dict(record.get('metadata', {}) or {})
        tc = self._task_config
        if tc is not None:
            tc_scan = self._load_scan_config(tc)
            # project_name 是运行时参数（用户每次提交指定，需唯一），从表单 scan_config 提到 metadata 顶层
            if tc_scan.get('project_name'):
                meta['project_name'] = tc_scan['project_name']
            meta['scan_config'] = {
                **(meta.get('scan_config') or {}),
                **{k: v for k, v in tc_scan.items() if k != 'project_name'},
            }
        return Sample(
            input=record.get('input') or f"Scan target: {meta.get('project_name', 'unknown')}",
            target=record.get('target', '') or '',
            metadata=meta,
        )

    # 调图灵 REST（不调 model.generate），拿回 finding 列表
    def run_inference(self, model: Model, sample: Sample, output_dir: str, **kwargs) -> TaskState:
        scan_cfg = (sample.metadata or {}).get('scan_config', {}) or {}
        project_name = (sample.metadata or {}).get('project_name', 'unknown')
        model_name = scan_cfg.get('model_name') or model.name or '(默认)'
        logger.info(f'[vuln_scan] 开始扫描 {project_name}（模型: {model_name}）...')
        dataset_name = os.path.basename(self._benchmark_meta.dataset_id)
        # source_path 相对 benchmark dataset 目录解析（部署无关；绝对路径直用）
        sp = scan_cfg.get('source_path', '')
        if sp and not os.path.isabs(sp):
            scan_cfg = {**scan_cfg, 'source_path': os.path.join(self._benchmark_meta.dataset_id, sp)}
        raw_findings = _run_async(_scan_async(scan_cfg, project_name, model_name, dataset_name))
        logger.info(f'[vuln_scan] {project_name} 扫描完成，finding 数={len(raw_findings)}')

        model_output = ModelOutput.from_content(
            model=model.name,
            content=json.dumps({'project': project_name, 'findings_count': len(raw_findings)},
                               ensure_ascii=False),
            stop_reason='stop',
        )
        model_output.metadata = {'findings_raw': raw_findings, 'project_name': project_name}
        return TaskState(
            model=model.name,
            sample=sample,
            messages=[ChatMessageUser(content=str(sample.input)), model_output.message],
            output=model_output,
            completed=True,
        )

    # 复用 matcher + metrics 算 TP/FP/FN/P/R/Coverage，按 vuln_type 分桶
    def match_score(self, original_prediction: str, filtered_prediction: str,
                    reference: str, task_state: TaskState) -> Score:
        raw = []
        if task_state.output is not None and task_state.output.metadata:
            raw = task_state.output.metadata.get('findings_raw', []) or []
        findings = parse_findings(raw)

        # GT 集成在 benchmark（datasets/<name>/gt.yaml），不依赖表单/record 配置
        gt_path = os.path.join(self._benchmark_meta.dataset_id, 'gt.yaml')
        gt_vulns = load_gt(gt_path).vulnerabilities

        mr = do_match(findings, gt_vulns)
        snap = compute_metrics(mr, findings, gt_vulns)

        score = Score(extracted_prediction=filtered_prediction, prediction=original_prediction)
        # F1 排首位：Report.score 取 metrics[0]（report.py:_set_score），首个 key
        # 决定顶部 Overall Score 卡片显示哪个指标 → 让它显示主分数 F1 而非 Precision。
        score.value.update({
            'Overall/F1': snap.f1,
            'Overall/Precision': snap.precision,
            'Overall/Recall': snap.recall,
            'Overall/Coverage': snap.coverage,
            'Overall/TP': snap.tp,
            'Overall/FP': snap.fp,
            'Overall/FN': snap.fn,
        })
        for b in snap.buckets:
            score.value[f'{b.vuln_type}/Precision'] = b.precision
            score.value[f'{b.vuln_type}/Recall'] = b.recall
            score.value[f'{b.vuln_type}/F1'] = b.f1
            score.value[f'{b.vuln_type}/TP'] = b.tp
            score.value[f'{b.vuln_type}/FP'] = b.fp
            score.value[f'{b.vuln_type}/FN'] = b.fn

        score.main_score_name = 'Overall/F1'
        score.explanation = (
            f'findings={len(findings)} gt={len(gt_vulns)} '
            f'TP={snap.tp} FP={snap.fp} FN={snap.fn} '
            f'P={snap.precision:.3f} R={snap.recall:.3f} Cov={snap.coverage:.3f}')
        return score
