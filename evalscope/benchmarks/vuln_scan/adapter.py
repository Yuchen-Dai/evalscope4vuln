# Copyright (c) Alibaba, Inc. and its affiliates.
# Vuln-Scan 通用 adapter：对接图灵平台做漏洞挖掘测评。
# 本文件只定义通用类；每个数据集由 registry_adapter.py 扫描 datasets/ 动态注册成 benchmark。
import asyncio
import json
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
        local_path=scan_cfg.get('local_path', '/tmp/vulnbench-target'),
        platforms=scan_cfg.get('platforms', 'web'),
        detect_types=scan_cfg.get('detect_types', ''),
        priority=str(scan_cfg.get('priority', '100')),
        model_name=scan_cfg.get('model_name', ''),
        max_concurrency=str(scan_cfg.get('max_concurrency', '')),
        phase1_timeout=str(scan_cfg.get('phase1_timeout', '')),
        phase2_timeout=str(scan_cfg.get('phase2_timeout', '')),
        phase3_timeout=str(scan_cfg.get('phase3_timeout', '')),
    )


async def _scan_async(scan_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """提交图灵扫描 → 轮询到完成 → 返回完整 finding 列表（原始 dict）。"""
    base_url = scan_cfg.get('turing_base_url') or vb_config.TURING_BASE_URL
    client = TuringClient(base_url=base_url)
    try:
        sc = _build_scan_config(scan_cfg)
        pid = await client.create_project(sc.display_name, sc.local_path)
        job_id = await client.submit_scan(pid, sc)
        logger.info(f'[vuln_scan] project={pid} job={job_id} 开始轮询...')
        deadline = time.time() + float(scan_cfg.get('timeout', vb_config.POLL_TIMEOUT))
        while True:
            await asyncio.sleep(vb_config.POLL_INTERVAL)
            try:
                st = await client.get_status(pid, job_id)
            except Exception as e:  # 单次查询失败不终止
                logger.warning(f'[vuln_scan] 状态查询失败: {e}')
                if time.time() > deadline:
                    break
                continue
            if st.get('status') == 'completed':
                break
            if time.time() > deadline:
                logger.warning('[vuln_scan] 轮询超时，取当前结果')
                break
        data = await client.get_report_data(pid, job_id)
        return data.get('findings') or []
    finally:
        await client.aclose()


class VulnBenchmarkAdapter(DefaultDataAdapter):
    """通用漏洞挖掘测评 adapter。每个数据集由 registry_adapter.py 注册成一个 benchmark。"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_aggregation_name = False   # 报告 metric_name 不带 mean_ 前缀

    # 本地 jsonl 加载（强制 LocalDataLoader）
    def load_from_disk(self, **kwargs):
        return super().load_from_disk(use_local_loader=True)

    # record → Sample：扫描配置与 GT 路径都放 metadata
    def record_to_sample(self, record: Dict[str, Any]) -> Sample:
        meta = dict(record.get('metadata', {}) or {})
        tc = self._task_config
        if tc is not None:
            # scan_config 透传 key 用本 benchmark 的 name（如 vuln_jeecgboot）
            name = self._benchmark_meta.name
            tc_scan = ((tc.dataset_args or {}).get(name, {}) or {}).get('scan_config', {}) or {}
            record_scan = meta.get('scan_config') or {}
            meta['scan_config'] = {
                **record_scan,
                **{k: v for k, v in tc_scan.items() if k not in ('repo_name', 'gt_file')},
            }
            if tc_scan.get('repo_name'):
                meta['repo_name'] = tc_scan['repo_name']
            if tc_scan.get('gt_file'):
                meta['gt_file'] = tc_scan['gt_file']
        return Sample(
            input=record.get('input') or f"Scan target: {meta.get('repo_name', 'unknown')}",
            target=record.get('target', '') or '',
            metadata=meta,
        )

    # 调图灵 REST（不调 model.generate），拿回 finding 列表
    def run_inference(self, model: Model, sample: Sample, output_dir: str, **kwargs) -> TaskState:
        scan_cfg = (sample.metadata or {}).get('scan_config', {}) or {}
        repo_name = (sample.metadata or {}).get('repo_name', 'unknown')
        logger.info(f'[vuln_scan] 开始扫描 {repo_name} ...')
        raw_findings = _run_async(_scan_async(scan_cfg))
        logger.info(f'[vuln_scan] {repo_name} 扫描完成，finding 数={len(raw_findings)}')

        model_output = ModelOutput.from_content(
            model=model.name,
            content=json.dumps({'repo': repo_name, 'findings_count': len(raw_findings)},
                               ensure_ascii=False),
            stop_reason='stop',
        )
        model_output.metadata = {'findings_raw': raw_findings, 'repo_name': repo_name}
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

        gt_file = (task_state.metadata or {}).get('gt_file')
        gt_vulns = load_gt(gt_file).vulnerabilities if gt_file else []

        mr = do_match(findings, gt_vulns)
        snap = compute_metrics(mr, findings, gt_vulns)

        score = Score(extracted_prediction=filtered_prediction, prediction=original_prediction)
        score.value.update({
            'Overall/Precision': snap.precision,
            'Overall/Recall': snap.recall,
            'Overall/F1': snap.f1,
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
