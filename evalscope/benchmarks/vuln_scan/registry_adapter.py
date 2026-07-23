# Copyright (c) Alibaba, Inc. and its affiliates.
# Vuln-Scan 动态注册：扫描 datasets/ 目录，每个数据集注册成一个 vuln_<name> benchmark。
# 文件名以 _adapter.py 结尾，被 evalscope benchmarks 的 glob 自动发现并 import，触发 _register_all()。
# 同时为每个 benchmark 生成 _meta/<name>.json（含 statistics.subset_stats），让 compute_eval_total_count
# 能算出 total → ProgressTracker 写 progress.json（否则 /progress 与 /eval/tasks 历史拿不到数据）。
import glob
import json
import os

from evalscope.api.benchmark import BenchmarkMeta
from evalscope.api.registry import register_benchmark
from evalscope.constants import OutputType, Tags

from evalscope.benchmarks.vuln_scan.adapter import VulnBenchmarkAdapter

_DATASETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'datasets')
_META_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '_meta')


def _count_samples(ds_dir: str) -> int:
    """读 default_test.jsonl 行数作为 sample_count（每行 = 一次图灵扫描）。"""
    dt = os.path.join(ds_dir, 'default_test.jsonl')
    if not os.path.exists(dt):
        return 1
    with open(dt, encoding='utf-8') as f:
        return sum(1 for line in f if line.strip())


def _write_meta(bench_name: str, ds_name: str, sample_count: int) -> None:
    """写 _meta/<name>.json，含 statistics.subset_stats（compute_eval_total_count 依赖它）。"""
    os.makedirs(_META_DIR, exist_ok=True)
    path = os.path.join(_META_DIR, f'{bench_name}.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump({
            'meta': {
                'name': bench_name,
                'pretty_name': f'Vuln-Scan: {ds_name}',
                'subset_list': ['default'],
            },
            'statistics': {
                'total_samples': sample_count,
                'subset_stats': [{'name': 'default', 'sample_count': sample_count}],
            },
        }, f, ensure_ascii=False)


def _register_all() -> None:
    """扫描 datasets/ 下每个子目录，注册成 vuln_<目录名> benchmark（共享 VulnBenchmarkAdapter）。"""
    for ds_dir in sorted(glob.glob(os.path.join(_DATASETS_DIR, '*'))):
        if not os.path.isdir(ds_dir):
            continue
        ds_name = os.path.basename(ds_dir)
        bench_name = f'vuln_{ds_name}'
        register_benchmark(BenchmarkMeta(
            name=bench_name,
            pretty_name=f'Vuln-Scan: {ds_name}',
            dataset_id=ds_dir,                  # 指向 datasets/<name>/（LocalDataLoader 找 default_test.jsonl）
            tags=[Tags.CUSTOM],
            metric_list=[],                     # match_score 自己算，不走 registry metric
            few_shot_num=0,
            train_split=None,
            eval_split='test',
            subset_list=['default'],
            default_subset='default',
            prompt_template='{question}',       # 占位（父类 process_sample_input 要求非 None），不调 LLM
            system_prompt=None,
            aggregation='mean',
            output_types=[OutputType.GENERATION],
            description=f'漏洞挖掘测评数据集：{ds_name}（对接图灵平台扫描，与 Ground Truth 比对）',
        ))(VulnBenchmarkAdapter)
        _write_meta(bench_name, ds_name, _count_samples(ds_dir))


_register_all()
