/**
 * Primary display score selection.
 *
 * The evaluation UI (Overall Score cards, evaluation list, overview tables)
 * shows ONE headline number per report. Historically that was `report.score`
 * (= `metrics[0]`, F1 on vuln benchmarks); the product decision is to headline
 * Coverage instead, so every surface selects the primary metric through this
 * shared helper rather than each picking `metrics[0]` on its own.
 *
 * Selection is read-time by metric name, so existing reports on disk (whose
 * `metrics[0]` is F1) switch to Coverage display without re-running.
 */

import type { ReportData } from '@/api/types'

const LOC_ONLY_PREFIX = 'LocOnly/'

/** vuln benchmark 的主展示指标：类型+位置口径下的 Overall/Coverage。 */
const PRIMARY_METRIC = 'Overall/Coverage'

/**
 * metric 名取末段（`LocOnly/Overall/Coverage` → `Coverage` / `Overall/F1` → `F1`）：
 * registry 按末段（或 overall_* 别名）识别；全串 `LocOnly/…` 归一后不在
 * registry/alias 表 → 会被误判非 bounded → 百分比/进度环失效。
 */
const lastSegment = (name: string): string => {
  const i = name.lastIndexOf('/')
  return i >= 0 ? name.slice(i + 1) : name
}

/**
 * 按 regime 取一个 report 的主展示分数与指标名。
 *
 * - vuln 报告：优先 Coverage（type: `Overall/Coverage` / loc:
 *   `LocOnly/Overall/Coverage`）。
 * - 非 vuln 报告（无 Coverage 指标）：回退 `metrics[0]`（`Report.score` 语义）；
 *   loc 模式再找 `LocOnly/${metrics[0].name}`，找不到回退 type 口径。
 *
 * 返回的 `metricName` 是末段纯指标名，可直接交给 `formatMetricByKey` /
 * `getBoundedMetricRatio` / `resolveMetricKey`。
 */
export function primaryMetricOf(
  report: ReportData,
  regime: 'type' | 'loc' = 'type',
): { score: number; metricName: string } {
  const primaryName = regime === 'loc' ? `${LOC_ONLY_PREFIX}${PRIMARY_METRIC}` : PRIMARY_METRIC
  const primary = report.metrics.find((m) => m.name === primaryName)
  if (primary) {
    return { score: primary.score, metricName: lastSegment(primary.name) }
  }

  const typeMetricName = report.metrics[0]?.name ?? 'score'
  if (regime === 'loc') {
    const locName = `${LOC_ONLY_PREFIX}${typeMetricName}`
    const m = report.metrics.find((x) => x.name === locName)
    if (m) return { score: m.score, metricName: lastSegment(locName) }
  }
  return { score: report.score, metricName: lastSegment(typeMetricName) }
}
