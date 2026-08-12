/**
 * 挖掘轨迹对比 tab：左 gt（漏洞）列表 + 右 N 列模型轨迹并排。
 * gt 列表与命中状态从各 report 的 getPredictions→Findings.gt 算（无需新端点）；
 * 选 gt 后调 compareTrajectory（后端按 gt_id 反查各模型 trajectory）。
 * 对齐轴 = gt_id；FP 无 gt 锚点不纳入。
 */
import { useEffect, useMemo, useState } from 'react'
import { getPredictions, compareTrajectory } from '@/api/reports'
import { useReports } from '@/contexts/ReportsContext'
import { isDomainError } from '@/api/errors'
import type { TrajectoryCompare } from '@/api/types'
import TrajectoryCompareView from './TrajectoryCompareView'
import Skeleton from '@/components/ui/Skeleton'
import ErrorAlert from '@/components/ui/ErrorAlert'

interface Props {
  reportNames: string[]
  rootPath: string
  displayLabels: Record<string, string>
}

interface GtItem {
  gt_id: string
  vuln_type?: string | null
  severity?: string | null
  title?: string | null
  matched_finding_ids?: string[]
  missed?: boolean
}

type Hit = 'tp' | 'fn' | '-'

function readGt(pred: unknown): GtItem[] {
  return ((pred as { Findings?: { gt?: GtItem[] } })?.Findings?.gt) || []
}

export default function TraceCompareTab({ reportNames, rootPath, displayLabels }: Props) {
  const { reportCache } = useReports()
  const [dataset, setDataset] = useState('')
  const [gtList, setGtList] = useState<GtItem[]>([])
  const [hits, setHits] = useState<Record<string, Record<string, Hit>>>({})
  const [selectedGt, setSelectedGt] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [traceLoading, setTraceLoading] = useState(false)
  const [compare, setCompare] = useState<TrajectoryCompare | null>(null)
  const [error, setError] = useState('')

  // 共同 vuln_ 数据集（仿 predCommonDatasets，过滤 vuln_）
  const commonVulnDs = useMemo(() => {
    if (reportNames.length < 2) return []
    const dsLists = reportNames.map((name) => {
      const cached = reportCache[name]
      const ds = cached ? (cached.datasets || []) : []
      return new Set(ds.filter((d: string) => d.startsWith('vuln_')))
    })
    if (dsLists.some((s) => s.size === 0)) return []
    return [...dsLists.reduce((a, b) => new Set([...a].filter((x) => b.has(x))))]
  }, [reportNames, reportCache])

  useEffect(() => {
    if (!dataset && commonVulnDs.length) setDataset(commonVulnDs[0])
  }, [commonVulnDs, dataset])

  // 拉 predictions → gt 列表 + 命中矩阵
  useEffect(() => {
    if (!dataset || reportNames.length < 2) return
    const controller = new AbortController()
    setLoading(true); setError('')
    Promise.all(reportNames.map((n) => getPredictions(rootPath, n, dataset, 'default', controller.signal)))
      .then((results) => {
        const preds = results.map((r) => r.predictions?.[0])
        const firstGt = preds.map(readGt).find((g) => g.length) || []
        setGtList(firstGt)
        if (firstGt.length) setSelectedGt(firstGt[0].gt_id)
        const matrix: Record<string, Record<string, Hit>> = {}
        for (const g of firstGt) {
          matrix[g.gt_id] = {}
          preds.forEach((p, i) => {
            const item = readGt(p).find((x) => x.gt_id === g.gt_id)
            if (item && (item.matched_finding_ids?.length || 0) > 0) matrix[g.gt_id][reportNames[i]] = 'tp'
            else if (item?.missed) matrix[g.gt_id][reportNames[i]] = 'fn'
            else matrix[g.gt_id][reportNames[i]] = '-'
          })
        }
        setHits(matrix)
      })
      .catch((e) => {
        if (!controller.signal.aborted && !(isDomainError(e) && e.kind === 'aborted')) setError(String(e))
      })
      .finally(() => !controller.signal.aborted && setLoading(false))
    return () => controller.abort()
  }, [rootPath, reportNames, dataset])

  // 选 gt → 拉对比轨迹
  useEffect(() => {
    if (!selectedGt || !dataset) return
    const controller = new AbortController()
    setTraceLoading(true); setCompare(null); setError('')
    compareTrajectory(rootPath, reportNames, dataset, selectedGt, controller.signal)
      .then((res) => !controller.signal.aborted && setCompare(res))
      .catch((e) => {
        if (!controller.signal.aborted && !(isDomainError(e) && e.kind === 'aborted')) setError(String(e))
      })
      .finally(() => !controller.signal.aborted && setTraceLoading(false))
    return () => controller.abort()
  }, [selectedGt, dataset, rootPath, reportNames])

  if (!commonVulnDs.length) {
    return <div className="text-sm text-[var(--text-muted)] p-4">这些报告无共同的 vuln_ 数据集，无法对比挖掘轨迹。</div>
  }
  if (loading) return <Skeleton lines={6} />

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2 text-sm">
        <span className="text-[var(--text-muted)]">数据集</span>
        <select value={dataset} onChange={(e) => setDataset(e.target.value)}
          className="px-2 py-1 rounded border border-[var(--border)] bg-[var(--bg-card)] text-sm">
          {commonVulnDs.map((d) => <option key={d} value={d}>{d}</option>)}
        </select>
      </div>
      {error && <ErrorAlert>{error}</ErrorAlert>}
      {!gtList.length ? (
        <div className="text-sm text-[var(--text-muted)] p-4">无 gt（漏洞）数据</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-3">
          {/* 左：gt 列表 */}
          <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] max-h-[75vh] overflow-y-auto">
            {gtList.map((g) => {
              const rowHits = hits[g.gt_id] || {}
              return (
                <button key={g.gt_id} onClick={() => setSelectedGt(g.gt_id)}
                  className={`w-full text-left px-3 py-2 border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-deep)] cursor-pointer transition-colors ${selectedGt === g.gt_id ? 'bg-[var(--bg-card2)]' : ''}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-[var(--text-muted)] truncate">{g.gt_id}</span>
                    {g.severity && <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent-dim)] text-[var(--accent)]">{g.severity}</span>}
                  </div>
                  <div className="text-sm truncate">{g.title || g.vuln_type || '(无标题)'}</div>
                  <div className="text-xs text-[var(--text-muted)] truncate">{g.vuln_type}</div>
                  {/* 各模型命中徽标 */}
                  <div className="flex items-center gap-1 mt-1">
                    {reportNames.map((n, i) => (
                      <span key={n} className="text-[10px] px-1 rounded" title={displayLabels[n] || n}
                        style={{ color: rowHits[n] === 'tp' ? 'var(--success, #3fb950)' : rowHits[n] === 'fn' ? 'var(--danger, #f85149)' : 'var(--text-muted)',
                                 border: `1px solid var(--compare-${i % 3}-border)` }}>
                        {(displayLabels[n]?.split('·')[0].trim() || n).slice(0, 8)} {rowHits[n] === 'tp' ? '✓' : rowHits[n] === 'fn' ? '✗' : '—'}
                      </span>
                    ))}
                  </div>
                </button>
              )
            })}
          </div>
          {/* 右：对比轨迹 */}
          <div className="min-w-0">
            {traceLoading ? <Skeleton lines={8} /> : compare ? (
              <TrajectoryCompareView runs={compare.runs} displayLabels={displayLabels} />
            ) : (
              <div className="text-sm text-[var(--text-muted)]">从左侧选择漏洞查看挖掘轨迹对比</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
