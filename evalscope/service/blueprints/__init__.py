# Copyright (c) Alibaba, Inc. and its affiliates.
"""Blueprint modules for EvalScope service."""

from .eval import bp_eval
from .reports import bp_reports
from .settings import bp_settings

__all__ = ['bp_eval', 'bp_reports', 'bp_settings']
