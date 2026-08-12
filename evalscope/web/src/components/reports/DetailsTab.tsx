import { useEffect, useMemo, useState } from 'react'
import { useLocale } from '@/contexts/LocaleContext'
import { getAnalysis, getDataFrame } from '@/api/reports'
import Card from '@/components/ui/Card'
import Table from '@/components/ui/Table'
import VulnScoreMatrix, { tryParseMatrix } from './VulnScoreMatrix'
import { scoreColor } from '@/utils/colorScale'
import { formatMetricByKey, getBoundedMetricRatio } from '@/domain/metric/registry'
import MarkdownRenderer from '@/components/common/MarkdownRenderer'
import Skeleton from '@/components/ui/Skeleton'

interface Props {
  reportName: string
  datasetName: string
  rootPath: string
  onSubsetClick?: (subset: string) => void
  overallScore?: number
  metricName?: string
  regime?: 'type' | 'loc'
}

const LOC_ONLY_PREFIX = 'LocOnly/'

export default function DetailsTab({ reportName, datasetName, rootPath, onSubsetClick, overallScore, metricName = 'score', regime = 'type' }: Props) {
  const { t } = useLocale()
  const [analysis, setAnalysis] = useState('')
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [subsetData, setSubsetData] = useState<{ columns: string[]; data: Record<string, unknown>[] }>({
    columns: [],
    data: [],
  })

  useEffect(() => {
    if (!datasetName || !reportName) return
    const controller = new AbortController()

    const load = async () => {
      setAnalysisLoading(true)
      try {
        const [analysisText, dfRes] = await Promise.all([
          getAnalysis(rootPath, reportName, datasetName, controller.signal).catch(() => ''),
          getDataFrame(rootPath, reportName, 'dataset', datasetName, controller.signal).catch(() => ({ columns: [], data: [] })),
        ])
        if (controller.signal.aborted) return
        setAnalysis(analysisText)
        setSubsetData({ columns: dfRes.columns, data: dfRes.data })
      } finally {
        if (!controller.signal.aborted) setAnalysisLoading(false)
      }
    }
    load()
    return () => controller.abort()
  }, [datasetName, reportName, rootPath])

  // Detect whether data has Metric column
  // 按 regime 过滤 subsetData.data：vuln benchmark 同一指标会有 `command-injection/F1`
  // 与 `LocOnly/command-injection/F1` 两套行，selector 切换时只展示对应一套。
  // 非 vuln（数据里无 LocOnly/ 行）不过滤，原样透传。
  const hasLocOnlyRows = useMemo(
    () => subsetData.data.some((r) => typeof r.Metric === 'string' && String(r.Metric).startsWith(LOC_ONLY_PREFIX)),
    [subsetData.data],
  )
  const filteredData = useMemo(() => {
    if (!hasLocOnlyRows) return subsetData.data
    if (regime === 'loc') {
      return subsetData.data
        .filter((r) => typeof r.Metric === 'string' && String(r.Metric).startsWith(LOC_ONLY_PREFIX))
        .map((r) => ({ ...r, Metric: String(r.Metric).slice(LOC_ONLY_PREFIX.length) }))
    }
    return subsetData.data.filter((r) => !(typeof r.Metric === 'string' && String(r.Metric).startsWith(LOC_ONLY_PREFIX)))
  }, [subsetData.data, regime, hasLocOnlyRows])

  const hasMetricCol = filteredData.length > 0 && 'Metric' in filteredData[0]

  // 漏洞 benchmark 的 Metric 形如 `vuln_type/指标` → pivot 成矩阵；否则回退扁平 Table
  const matrixModel = useMemo(() => tryParseMatrix(filteredData), [filteredData])

  const subsetColumns = [
    {
      key: 'Subset',
      label: 'Subset',
      sortable: true,
      render: (row: Record<string, unknown>) => {
        const name = String(row.Subset ?? '')
        if (onSubsetClick) {
          return (
            <button
              onClick={() => onSubsetClick(name)}
              className="text-[var(--accent)] hover:underline cursor-pointer bg-transparent border-none p-0 font-inherit text-left"
              title={t('reportDetail.viewPredictions')}
            >
              {name}
            </button>
          )
        }
        return <span>{name}</span>
      },
    },
    ...(hasMetricCol ? [{
      key: 'Metric',
      label: t('reportDetail.metric'),
      sortable: true,
      render: (row: Record<string, unknown>) => (
        <span className="text-[var(--text-muted)] text-xs font-mono">{String(row.Metric ?? '')}</span>
      ),
    }] : []),
    {
      key: 'Score',
      label: 'Score',
      sortable: true,
      render: (row: Record<string, unknown>) => {
        const score = Number(row.Score ?? 0)
        const rowMetricName = String(row.Metric ?? metricName)
        const ratio = getBoundedMetricRatio(rowMetricName, score)
        // Inline score bar
        return (
          <div className="flex items-center gap-2">
            {ratio != null && (
              <div className="h-1.5 w-[60px] min-w-[60px] rounded-full bg-[var(--border)] overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-300"
                  style={{ width: `${ratio * 100}%`, background: scoreColor(ratio) }}
                />
              </div>
            )}
            <span className="font-mono font-medium tabular-nums" style={{ color: ratio == null ? 'var(--text)' : scoreColor(ratio) }}>
              {formatMetricByKey(rowMetricName, score, t).primary}
            </span>
          </div>
        )
      },
    },
    {
      key: 'Num',
      label: 'Num',
      sortable: true,
      render: (row: Record<string, unknown>) => (
        <span className="text-[var(--text-muted)]">{Number(row.Num ?? 0).toLocaleString()}</span>
      ),
    },
  ]

  const normOverall = getBoundedMetricRatio(metricName, overallScore)

  return (
    <div className="flex flex-col gap-6">
      {/* Overall Score Stat */}
      {overallScore != null && (
        <div className="flex items-center gap-3 p-4 rounded-[var(--radius)] bg-[var(--bg-card2)] border border-[var(--border)]">
          <div className="flex flex-col gap-0.5">
            <span className="text-xs text-[var(--text-muted)] uppercase tracking-wide">
              {t('reportDetail.overallScore')}
            </span>
            <span
              className="text-3xl font-bold font-mono tabular-nums"
              style={{ color: normOverall == null ? 'var(--text)' : scoreColor(normOverall) }}
            >
              {formatMetricByKey(metricName, overallScore, t).primary}
            </span>
          </div>
          {normOverall != null && (
            <svg width="48" height="48" viewBox="0 0 48 48" style={{ transform: 'rotate(-90deg)' }}>
              <circle cx="24" cy="24" r="19" fill="none" stroke="var(--border)" strokeWidth="6" />
              <circle
                cx="24" cy="24" r="19" fill="none"
                stroke={scoreColor(normOverall)}
                strokeWidth="6"
                strokeDasharray={`${2 * Math.PI * 19}`}
                strokeDashoffset={`${2 * Math.PI * 19 * (1 - normOverall)}`}
                strokeLinecap="round"
              />
            </svg>
          )}
        </div>
      )}

      {/* Subset Scores Table */}
      {filteredData.length > 0 && (
        <Card title={t('reportDetail.subsetScores')}>
          {matrixModel ? (
            <VulnScoreMatrix model={matrixModel} />
          ) : (
            <Table
              columns={subsetColumns}
              data={filteredData}
              defaultSort={{ key: 'Score', dir: 'desc' }}
            />
          )}
        </Card>
      )}

      {/* AI Analysis */}
      <Card title={t('reportDetail.analysis')}>
        {analysisLoading ? (
          <Skeleton lines={5} />
        ) : analysis && analysis !== 'N/A' ? (
          <MarkdownRenderer content={analysis} />
        ) : (
          <p className="text-sm text-[var(--text-muted)]">{t('common.noData')}</p>
        )}
      </Card>

      {/* Score Distribution Chart removed - info already visible in Subset Scores table */}
    </div>
  )
}
