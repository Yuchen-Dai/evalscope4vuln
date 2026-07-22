"""GT schema 归属（从 schemas 重新导出，便于 `from dataset.gt_schema import GroundTruth`）。"""
from evalscope.benchmarks.vuln_scan.schemas import GroundTruth, GtLocation, GtVuln

__all__ = ["GroundTruth", "GtLocation", "GtVuln"]
