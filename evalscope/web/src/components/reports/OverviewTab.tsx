import { useMemo, useState } from 'react'
import { Radar, Table2 } from 'lucide-react'
import { useLocale } from '@/contexts/LocaleContext'
import type { ReportData } from '@/api/types'
import { getChartUrl } from '@/api/reports'
import Card from '@/components/ui/Card'
import Table from '@/components/ui/Table'
import { formatMetricByKey, getBoundedMetricRatio, getMetricSpec, resolveMetricKey } from '@/domain/metric/registry'
import PlotlyChart from '@/components/charts/PlotlyChart'
import ReportSummaryStats from './ReportSummaryStats'
import JsonViewer from '@/components/common/JsonViewer'

interface Props {
  reports: ReportData[]
  reportName: string
  rootPath: string
  taskConfig?: Record<string, unknown>
  onDatasetClick?: (dataset: string) => void
  regime?: 'type' | 'loc'
}

const LOC_ONLY_PREFIX = 'LocOnly/'

// metric 名取末段（`LocOnly/Overall/F1` → `F1` / `Overall/F1` → `F1`）：
// registry 按末段别名识别，全串 `LocOnly/Overall/F1` 归一成 `loconly_overall_f1`
// 不在 registry/alias 表 → 误判非 bounded → 百分比/进度环失效。
const lastSegment = (name: string): string => {
  const i = name.lastIndexOf('/')
  return i >= 0 ? name.slice(i + 1) : name
}

// 按 regime 取每个 report 的总体分数与 metric 名：type 用 report.score + metrics[0]；
// loc 从 metrics 找 `LocOnly/${metrics[0].name}`，找不到回退 type 字段。
function primaryOf(report: ReportData, regime: 'type' | 'loc'): { score: number; metricName: string } {
  const typeMetricName = report.metrics[0]?.name ?? 'score'
  if (regime === 'loc') {
    const locName = `${LOC_ONLY_PREFIX}${typeMetricName}`
    const m = report.metrics.find((x) => x.name === locName)
    if (m) return { score: m.score, metricName: lastSegment(locName) }
  }
  return { score: report.score, metricName: typeMetricName }
}

export default function OverviewTab({ reports, reportName, rootPath, taskConfig, onDatasetClick, regime = 'type' }: Props) {
  const { t } = useLocale()
  const [scoreView, setScoreView] = useState<'table' | 'radar'>('table')
  const metricKeys = reports.map((report) => resolveMetricKey(primaryOf(report, regime).metricName))
  const canShowRadar = reports.length >= 3
    && metricKeys.every((key) => key === metricKeys[0])
    && getMetricSpec(metricKeys[0] ?? '').spec.boundedness === 'bounded'

  const tableData = useMemo(() => {
    return reports.map((r) => {
      const p = primaryOf(r, regime)
      return {
        Dataset: r.dataset_name,
        Score: p.score,
        Metric: p.metricName,
        Samples: r.metrics[0]?.categories?.reduce((s, c) => s + c.num, 0) ?? 0,
      }
    })
  }, [reports, regime])

  const columns = [
    {
      key: 'Dataset',
      label: 'Dataset',
      sortable: true,
      render: (row: Record<string, unknown>) => {
        const name = String(row.Dataset)
        const content = (
          <>
            <span className="block max-w-[72px] break-words sm:max-w-none">{name}</span>
            <span className="mt-0.5 block text-[10px] text-[var(--text-muted)] sm:hidden">
              {Number(row.Samples).toLocaleString()} {t('single.samples')}
            </span>
          </>
        )
        if (onDatasetClick) {
          return (
            <button
              onClick={() => onDatasetClick(name)}
              className="text-[var(--accent)] hover:underline cursor-pointer bg-transparent border-none p-0 font-inherit text-left"
            >
              {content}
            </button>
          )
        }
        return content
      },
    },
    {
      key: 'Score',
      label: 'Score',
      sortable: true,
      render: (row: Record<string, unknown>) => {
        const score = Number(row.Score)
        const metricName = String(row.Metric ?? 'score')
        const ratio = getBoundedMetricRatio(metricName, score)
        return (
          <div className="flex min-w-[92px] items-center justify-end gap-1.5 sm:min-w-[240px] sm:gap-3">
            {ratio != null && (
              <div className="h-2 min-w-9 flex-1 overflow-hidden rounded-full border border-[var(--border)] bg-[var(--bg-deep)] sm:h-2.5">
                <div
                  role="progressbar"
                  aria-label={`${String(row.Dataset)} ${t('prediction.score')}`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={Math.round(ratio * 100)}
                  className="h-full rounded-full transition-all duration-300"
                  style={{ width: `${ratio * 100}%`, background: 'var(--accent)' }}
                />
              </div>
            )}
            <span className="min-w-12 text-right font-mono text-xs font-semibold tabular-nums text-[var(--text)] sm:text-sm">
              {formatMetricByKey(metricName, score, t).primary}
            </span>
          </div>
        )
      },
    },
    {
      key: 'Samples',
      label: 'Samples',
      sortable: true,
      headerClassName: 'hidden sm:table-cell',
      cellClassName: 'hidden sm:table-cell',
      render: (row: Record<string, unknown>) => (
        <span className="text-[var(--text-muted)]">{Number(row.Samples).toLocaleString()}</span>
      ),
    },
  ]

  return (
    <div className="flex flex-col gap-6">
      {/* Summary Stats */}
      <ReportSummaryStats reports={reports} regime={regime} />

      <Card title={t('single.datasetScores')}>
        {canShowRadar && (
          <div className="mb-4 flex justify-end">
            <div className="inline-flex rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-deep)] p-1">
              {([
                ['table', t('single.tableView'), Table2],
                ['radar', t('single.radarView'), Radar],
              ] as const).map(([view, label, Icon]) => (
                <button
                  key={view}
                  type="button"
                  aria-pressed={scoreView === view}
                  onClick={() => setScoreView(view)}
                  className={`inline-flex min-h-9 items-center gap-1.5 rounded-[var(--radius-xs)] px-3 type-button-sm transition-colors ${
                    scoreView === view
                      ? 'bg-[var(--bg-card)] text-[var(--text)] shadow-[var(--shadow-sm)]'
                      : 'text-[var(--text-muted)] hover:text-[var(--text)]'
                  }`}
                >
                  <Icon size={14} aria-hidden="true" />
                  {label}
                </button>
              ))}
            </div>
          </div>
        )}

        {scoreView === 'radar' && canShowRadar ? (
          <PlotlyChart
            src={getChartUrl(rootPath, 'radar', { reportName })}
            height={400}
            fallbackTable={{
              columns: ['Dataset', 'Score', 'Samples'],
              rows: tableData,
              scoreColumns: ['Score'],
            }}
          />
        ) : (
          <Table
            columns={columns}
            data={tableData}
            defaultSort={{ key: 'Score', dir: 'desc' }}
            className="[&_th]:px-2 [&_td]:px-2 sm:[&_th]:px-4 sm:[&_td]:px-4"
          />
        )}
      </Card>

      {/* Task Config */}
      {taskConfig && Object.keys(taskConfig).length > 0 && (
        <Card title={t('reportDetail.taskConfig')} collapsible>
          <JsonViewer value={taskConfig} maxHeight={400} />
        </Card>
      )}
    </div>
  )
}
