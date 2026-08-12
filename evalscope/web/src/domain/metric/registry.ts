/**
 * Metric registry: the domain-organized catalog of `MetricDisplaySpec` entries
 * plus the single, centralized formatting entry point used across the UI.
 *
 * Rather than letting each surface re-derive precision, units and percentage
 * semantics (previously scattered across `src/utils/scoreUtils.ts` and
 * `src/utils/formatUtils.ts` via ad-hoc `toFixed` calls), every metric is looked
 * up here by its implementation-level key and rendered through the shared
 * `formatMetric` primitive. This guarantees that the same metric renders with
 * identical precision, rounding and units on every view.
 *
 * The display form of each metric is decided from its spec metadata, never
 * inferred from the magnitude of a value.
 */

import type { FormattedMetric } from './metricFormat'
import { formatMetric } from './metricFormat'
import type { MetricDisplaySpec, MetricRegistry } from './MetricDisplaySpec'
import {
  DEFAULT_PERCENT_PRECISION,
  DEFAULT_RAW_PRECISION,
  resolveSpec,
} from './MetricDisplaySpec'

/** Translate function contract shared with `formatMetric`. */
type Translate = (key: string) => string

/**
 * Evaluation-domain metrics.
 *
 * These are Bounded_Ratio_Metrics stored as a 0-1 ratio: they render as a
 * percentage primary (1 decimal, round half up) with a 0-1 raw value (4
 * decimals) for tooltips and exports. `higher-is-better` for all
 * accuracy-style scores.
 */
export const EVALUATION_METRIC_SPECS: MetricRegistry = {
  accuracy: {
    key: 'accuracy',
    labelKey: 'metrics.accuracy',
    boundedness: 'bounded',
    direction: 'higher-is-better',
    unit: null,
    rawPrecision: DEFAULT_RAW_PRECISION,
    percentPrecision: DEFAULT_PERCENT_PRECISION,
  },
  pass_rate: {
    key: 'pass_rate',
    labelKey: 'metrics.pass_rate',
    boundedness: 'bounded',
    direction: 'higher-is-better',
    unit: null,
    rawPrecision: DEFAULT_RAW_PRECISION,
    percentPrecision: DEFAULT_PERCENT_PRECISION,
  },
  exact_match: {
    key: 'exact_match',
    labelKey: 'metrics.exact_match',
    boundedness: 'bounded',
    direction: 'higher-is-better',
    unit: null,
    rawPrecision: DEFAULT_RAW_PRECISION,
    percentPrecision: DEFAULT_PERCENT_PRECISION,
  },
  f1: {
    key: 'f1',
    labelKey: 'metrics.f1',
    boundedness: 'bounded',
    direction: 'higher-is-better',
    unit: null,
    rawPrecision: DEFAULT_RAW_PRECISION,
    percentPrecision: DEFAULT_PERCENT_PRECISION,
  },
  precision: {
    key: 'precision',
    labelKey: 'metrics.precision',
    boundedness: 'bounded',
    direction: 'higher-is-better',
    unit: null,
    rawPrecision: DEFAULT_RAW_PRECISION,
    percentPrecision: DEFAULT_PERCENT_PRECISION,
  },
  recall: {
    key: 'recall',
    labelKey: 'metrics.recall',
    boundedness: 'bounded',
    direction: 'higher-is-better',
    unit: null,
    rawPrecision: DEFAULT_RAW_PRECISION,
    percentPrecision: DEFAULT_PERCENT_PRECISION,
  },
  score_percent: {
    key: 'score_percent',
    labelKey: 'metrics.accuracy',
    boundedness: 'bounded',
    direction: 'higher-is-better',
    unit: null,
    rawPrecision: DEFAULT_RAW_PRECISION,
    percentPrecision: DEFAULT_PERCENT_PRECISION,
    storedAsHundred: true,
  },
}

/**
 * The merged, application-wide metric registry. All evaluation specs are
 * combined into a single lookup table so any surface can resolve a metric by
 * its key through one entry point.
 */
export const METRIC_REGISTRY: MetricRegistry = {
  ...EVALUATION_METRIC_SPECS,
}

/**
 * Alias map from common backend/UI spellings to canonical registry keys.
 *
 * Keys are normalized (lower-cased, non-alphanumeric characters collapsed to
 * `_`) before lookup, so variants such as `Average Accuracy`, `pass@1` or
 * `Overall/F1` all resolve to a single canonical spec. Anything not listed
 * here (and not a direct registry key) falls through to the default fallback
 * spec, preserving the "undefined display form" contract.
 */
const METRIC_ALIASES: Record<string, string> = {
  acc: 'accuracy',
  average_accuracy: 'accuracy',
  averageaccuracy: 'accuracy',
  weightedaverageaccuracy: 'accuracy',
  weighted_average_accuracy: 'accuracy',
  score: 'accuracy',
  avg_score: 'accuracy',
  mean_acc: 'accuracy',
  strict_pass: 'pass_rate',
  required_coverage: 'accuracy',
  net_match_score: 'accuracy',
  boundary_precision: 'precision',
  compliance_score: 'accuracy',
  pass_at_k: 'pass_rate',
  pass_hat_k: 'pass_rate',
  pass_1: 'pass_rate',
  'pass@1': 'pass_rate',
  passrate: 'pass_rate',
  pass_rate: 'pass_rate',
  em: 'exact_match',
  exactmatch: 'exact_match',
  f1_score: 'f1',
  f1score: 'f1',
  temporal_f1: 'f1',
  task_averaged_f1: 'f1',
  overall_f1: 'f1',
  weighted_score_percent: 'score_percent',
  weightedscorepercent: 'score_percent',
}

/**
 * Normalize an arbitrary metric key to its canonical registry key.
 *
 * The raw key is lower-cased and any run of non-alphanumeric characters is
 * collapsed to a single underscore before alias resolution. A key that is
 * already a canonical registry key is returned unchanged; an unknown key is
 * returned normalized so the caller can still attempt a direct lookup (and fall
 * back to the default spec on a miss).
 *
 * @param key Raw, implementation-level metric key.
 * @returns The canonical registry key when known, otherwise the normalized key.
 */
export function resolveMetricKey(key: string): string {
  if (key in METRIC_REGISTRY) {
    return key
  }
  const normalized = key
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9@]+/g, '_')
    .replace(/^_+|_+$/g, '')
  const candidates = [normalized, normalized.replace(/^(mean|sum)_/, '')]
  for (const candidate of candidates) {
    if (candidate in METRIC_REGISTRY) {
      return candidate
    }
    if (candidate in METRIC_ALIASES) {
      return METRIC_ALIASES[candidate]
    }
  }
  return normalized
}

/**
 * Resolve the `MetricDisplaySpec` for a metric key, applying alias
 * normalization. On a registry miss the shared `DEFAULT_METRIC_SPEC` is returned
 * (via `resolveSpec`), signalling an undefined display form to the UI.
 *
 * @param key Raw metric key.
 * @param registry Registry to resolve against (defaults to `METRIC_REGISTRY`).
 * @returns The resolved spec together with a `isFallback` indicator.
 */
export function getMetricSpec(
  key: string,
  registry: MetricRegistry = METRIC_REGISTRY,
): { spec: MetricDisplaySpec; isFallback: boolean } {
  return resolveSpec(resolveMetricKey(key), registry)
}

/**
 * Centralized formatting entry point: format a metric value by its key.
 *
 * This is the single call site every surface should use to render a metric. It
 * resolves the key to a `MetricDisplaySpec` (with alias normalization and
 * default fallback) and delegates to the pure `formatMetric` primitive, so
 * precision, rounding and units stay consistent everywhere.
 *
 * @param key Raw metric key (canonical key or a known alias/spelling).
 * @param value Raw metric value; `null` / `undefined` / `NaN` render as missing.
 * @param t Locale translate function used to resolve unit labels.
 * @param registry Registry to resolve against (defaults to `METRIC_REGISTRY`).
 * @returns The display-ready `FormattedMetric`.
 */
export function formatMetricByKey(
  key: string,
  value: number | null | undefined,
  t: Translate,
  registry: MetricRegistry = METRIC_REGISTRY,
): FormattedMetric {
  const { spec } = getMetricSpec(key, registry)
  return formatMetric(value, spec, t)
}

/** Return a clamped 0-1 ratio only when the metric contract is bounded. */
export function getBoundedMetricRatio(key: string, value: number | null | undefined): number | null {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return null
  }
  const { spec } = getMetricSpec(key)
  if (spec.boundedness !== 'bounded') {
    return null
  }
  const ratio = spec.storedAsHundred ? value / 100 : value
  return Math.max(0, Math.min(1, ratio))
}

/**
 * Thin convenience wrapper returning only the primary display string for a
 * metric key. Intended as the drop-in replacement for scattered
 * `score.toFixed(n)` call sites during the incremental migration.
 *
 * @param key Raw metric key.
 * @param value Raw metric value.
 * @param t Locale translate function.
 * @param registry Registry to resolve against (defaults to `METRIC_REGISTRY`).
 * @returns The primary display text (percentage, unit-suffixed raw, or the
 *   missing placeholder).
 */
export function formatScore(
  key: string,
  value: number | null | undefined,
  t: Translate,
  registry: MetricRegistry = METRIC_REGISTRY,
): string {
  return formatMetricByKey(key, value, t, registry).primary
}
