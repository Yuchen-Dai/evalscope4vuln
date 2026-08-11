import { useMemo } from 'react'
import { useLocale } from '@/contexts/LocaleContext'
import type { ReportData } from '@/api/types'
import { scoreColor } from '@/utils/colorScale'
import { formatScore, getBoundedMetricRatio, resolveMetricKey } from '@/domain/metric/registry'

interface Props {
  reports: ReportData[]
  regime?: 'type' | 'loc'
}

const LOC_ONLY_PREFIX = 'LocOnly/'

// metric 名取末段（`LocOnly/Overall/F1` → `F1`）：registry 按末段别名识别，
// 全串归一成 `loconly_overall_f1` 不在 registry/alias 表 → 误判非 bounded
// → 百分比缺失 + 进度环消失。type 模式的 `Overall/F1` 经 overall_f1 别名可识别。
const lastSegment = (name: string): string => {
  const i = name.lastIndexOf('/')
  return i >= 0 ? name.slice(i + 1) : name
}

// 按 regime 取每个 report 的总体分数与 metric 名（与 OverviewTab.primaryOf 同语义）。
function primaryOf(report: ReportData, regime: 'type' | 'loc'): { score: number; metricName: string } {
  const typeMetricName = report.metrics[0]?.name ?? 'score'
  if (regime === 'loc') {
    const locName = `${LOC_ONLY_PREFIX}${typeMetricName}`
    const m = report.metrics.find((x) => x.name === locName)
    if (m) return { score: m.score, metricName: lastSegment(locName) }
  }
  return { score: report.score, metricName: typeMetricName }
}

/** SVG circular progress ring — 8px stroke (DESIGN.md `{components.score-ring}`). */
function ScoreRing({ score, size = 80 }: { score: number; size?: number }) {
  const stroke = 8
  const r = (size - stroke) / 2
  const circ = 2 * Math.PI * r
  const offset = circ * (1 - Math.max(0, Math.min(1, score)))
  const color = scoreColor(score)
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: 'rotate(-90deg)', flexShrink: 0 }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border)" strokeWidth={stroke} />
      <circle
        cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={color}
        strokeWidth={stroke}
        strokeDasharray={circ}
        strokeDashoffset={offset}
        strokeLinecap="round"
        style={{ transition: 'stroke-dashoffset 0.7s ease' }}
      />
    </svg>
  )
}

export default function ReportSummaryStats({ reports, regime = 'type' }: Props) {
  const { t } = useLocale()

  const stats = useMemo(() => {
    if (!reports.length) return null

    const entries = reports.map((report) => {
      const p = primaryOf(report, regime)
      return { name: report.dataset_name, score: p.score, metricName: p.metricName }
    })
    const metricKey = resolveMetricKey(entries[0].metricName)
    const comparable = entries.every((entry) => resolveMetricKey(entry.metricName) === metricKey)
    const scores = entries.map((entry) => entry.score)
    const avg = comparable ? scores.reduce((s, v) => s + v, 0) / scores.length : null

    const bestIdx = scores.indexOf(Math.max(...scores))
    const worstIdx = scores.indexOf(Math.min(...scores))

    const totalSamples = reports.reduce((sum, r) => {
      return sum + (r.metrics[0]?.categories?.reduce((s, c) => s + c.num, 0) ?? 0)
    }, 0)

    return {
      avg,
      metricName: entries[0].metricName,
      best: comparable ? { name: entries[bestIdx].name, score: scores[bestIdx] } : null,
      worst: comparable ? { name: entries[worstIdx].name, score: scores[worstIdx] } : null,
      totalSamples,
    }
  }, [reports, regime])

  if (!stats) return null

  const scoreCards = stats.avg == null || stats.best == null || stats.worst == null ? [] : [
    { label: t('reportDetail.avgScore'), value: stats.avg },
    { label: t('reportDetail.bestDataset'), value: stats.best.score, sub: stats.best.name },
    { label: t('reportDetail.worstDataset'), value: stats.worst.score, sub: stats.worst.name },
  ].map((card) => ({
    ...card,
    norm: getBoundedMetricRatio(stats.metricName, card.value),
    display: formatScore(stats.metricName, card.value, t),
  }))

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {/* Score ring cards */}
      {scoreCards.map((card, i) => (
        <div
          key={i}
          className="flex items-center gap-3 p-4 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)]"
        >
          {card.norm != null && <ScoreRing score={card.norm} size={72} />}
          <div className="flex flex-col gap-0.5 min-w-0">
            <span className="type-table-xs">
              {card.label}
            </span>
            <span
              className="text-xl font-bold font-mono tabular-nums leading-tight"
              style={{ color: card.norm == null ? 'var(--text)' : scoreColor(card.norm) }}
            >
              {card.display}
            </span>
            {card.sub && (
              <span className="text-xs text-[var(--text-muted)] break-words min-w-0" title={card.sub}>
                {card.sub}
              </span>
            )}
          </div>
        </div>
      ))}

      {/* Total Samples — plain number card */}
      <div className="flex flex-col justify-center gap-1 p-4 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)]">
        <span className="type-table-xs">
          {t('reportDetail.totalSamples')}
        </span>
        <span className="text-2xl font-bold font-mono tabular-nums text-[var(--accent)]">
          {stats.totalSamples.toLocaleString()}
        </span>
      </div>
    </div>
  )
}
