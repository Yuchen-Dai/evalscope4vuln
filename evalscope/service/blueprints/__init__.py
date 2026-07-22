# Copyright (c) Alibaba, Inc. and its affiliates.
"""Blueprint modules for EvalScope service."""

from .eval import bp_eval
from .reports import bp_reports

__all__ = ['bp_eval', 'bp_reports']
