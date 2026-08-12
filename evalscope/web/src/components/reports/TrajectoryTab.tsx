/**
 * 挖掘轨迹 tab：左侧 finding 列表 → 选 finding 拉各阶段 session 轨迹 → 右侧 TrajectoryView。
 * 数据：报告 findings（getPredictions）+ /trace/for-finding（getTraceForFinding，经图灵拉真实 sessions）。
 */
import { useEffect, useState } from 'react'
import { getPredictions, getTraceForFinding } from '@/api/reports'
import { isDomainError } from '@/api/errors'
import type { PredictionRow, Trajectory } from '@/api/types'
import TrajectoryView from './TrajectoryView'
import Skeleton from '@/components/ui/Skeleton'
import ErrorAlert from '@/components/ui/ErrorAlert'

interface Props {
  reportName: string
  datasetName: string
  rootPath: string
}

interface FindingItem {
  task_id?: string | null
  finding_id?: string | null
  detection_id?: string | null
  detection_source_task_id?: string | null
  display_id?: string | null
  vuln_type?: string | null
  severity?: string | null
  title?: string | null
  classification?: string | null
  raw?: Record<string, unknown> | null
}

export default function TrajectoryTab({ reportName, datasetName, rootPath }: Props) {
  const [findings, setFindings] = useState<FindingItem[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [trajectory, setTrajectory] = useState<Trajectory | null>(null)
  const [loading, setLoading] = useState(false)
  const [traceLoading, setTraceLoading] = useState(false)
  const [error, setError] = useState('')

  // 拉 findings（报告 predictions）
  useEffect(() => {
    if (!datasetName.startsWith('vuln_') || !reportName) return
    const controller = new AbortController()
    setLoading(true); setError('')
    getPredictions(rootPath, reportName, datasetName, 'default', controller.signal)
      .then((res: { predictions: PredictionRow[] }) => {
        const f = res.predictions.flatMap((p) => p.Findings?.findings || [])
        setFindings(f)
        if (f.length) setSelected(f[0].finding_id || null)
      })
      .catch((e) => {
        if (!controller.signal.aborted && !(isDomainError(e) && e.kind === 'aborted'))
          setError(String(e))
      })
      .finally(() => !controller.signal.aborted && setLoading(false))
    return () => controller.abort()
  }, [rootPath, reportName, datasetName])

  // 选 finding → 拉 trajectory
  useEffect(() => {
    const f = findings.find((x) => x.finding_id === selected)
    if (!f) return
    const controller = new AbortController()
    setTraceLoading(true); setTrajectory(null); setError('')
    const taskId = (f.task_id as string) || (f.raw?.task_id as string) || f.finding_id || ''
    getTraceForFinding(rootPath, reportName, datasetName, taskId, f.finding_id || undefined, f.vuln_type || undefined, f.detection_id || undefined, f.detection_source_task_id || undefined, controller.signal)
      .then((traj) => !controller.signal.aborted && setTrajectory(traj))
      .catch((e) => {
        if (!controller.signal.aborted && !(isDomainError(e) && e.kind === 'aborted'))
          setError(String(e))
      })
      .finally(() => !controller.signal.aborted && setTraceLoading(false))
    return () => controller.abort()
  }, [selected, findings, rootPath, reportName, datasetName])

  if (loading) return <Skeleton lines={6} />

  return (
    <div className="flex flex-col gap-3">
      {error && <ErrorAlert>{error}</ErrorAlert>}
      {!findings.length && !loading ? (
        <div className="text-sm text-[var(--text-muted)] p-4">
          无 findings（非 vuln benchmark 或无数据）
        </div>
      ) : findings.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-3">
          {/* 左：finding 列表 */}
          <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] max-h-[75vh] overflow-y-auto">
            {findings.map((f) => (
              <button
                key={f.finding_id || f.display_id || f.task_id}
                onClick={() => setSelected(f.finding_id || null)}
                className={`w-full text-left px-3 py-2 border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-deep)] cursor-pointer transition-colors ${selected === f.finding_id ? 'bg-[var(--bg-card2)]' : ''}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-mono text-[var(--text-muted)]">{f.display_id || f.finding_id}</span>
                  {f.severity && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent-dim)] text-[var(--accent)]">{f.severity}</span>
                  )}
                </div>
                <div className="text-sm truncate">{f.title || f.vuln_type || '(无标题)'}</div>
                <div className="text-xs text-[var(--text-muted)] truncate">{f.vuln_type}</div>
              </button>
            ))}
          </div>
          {/* 右：轨迹 */}
          <div className="min-w-0">
            {traceLoading ? (
              <Skeleton lines={8} />
            ) : trajectory ? (
              <TrajectoryView trajectory={trajectory} />
            ) : (
              <div className="text-sm text-[var(--text-muted)]">从左侧选择 finding 查看挖掘轨迹</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
