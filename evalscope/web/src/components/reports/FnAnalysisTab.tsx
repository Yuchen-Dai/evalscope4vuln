/**
 * 漏报分析 tab（ReportDetail 与「挖掘轨迹」并列）：统一分析当前数据集的全部漏报(FN)。
 * 左列 FN 列表（分析状态徽标），右侧详情 = GT 信息 + 中断 banner（在哪一步中断）+
 * agent 重构的中断轨迹时间线（复用 TrajectoryView + breakpoint 高亮）+ 结构化建议卡。
 * 任务态服务端化（invoke 异步 + progress 轮询），切走切回可恢复；opencode 结论经
 * MCP staging 增量落盘，分析中即可读到已提交条目。
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { usePolling } from '@/hooks/usePolling'
import { useLocale } from '@/contexts/LocaleContext'
import type { FnAdvice, FnAdviceProgress, PredictionRow } from '@/api/types'
import { fnTraceSchema } from '@/api/schemas/reports.schema'
import { getFnAdvice, getFnAdviceProgress, getPredictions, startFnAdviceTask, stopFnAdviceTask } from '@/api/reports'
import { isDomainError } from '@/api/errors'
import { groupFnTraceSteps, TRACE_STAGE_LABEL_KEY } from '@/domain/fnTrace'
import TrajectoryView from './TrajectoryView'
import FnAdviceCard from './FnAdviceCard'
import EmptyStateSystem from '@/components/common/EmptyStateSystem'
import Skeleton from '@/components/ui/Skeleton'
import ErrorAlert from '@/components/ui/ErrorAlert'

type FnGtRow = NonNullable<PredictionRow['Findings']>['gt'][number]

interface Props {
  reportName: string
  datasetName: string
  rootPath: string
  /** 从漏洞结果页「去漏报分析」跳入时预选的 gt_id */
  initialGtId?: string
}

export default function FnAnalysisTab({ reportName, datasetName, rootPath, initialGtId }: Props) {
  const { t } = useLocale()
  const [predictions, setPredictions] = useState<PredictionRow[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [selectedGt, setSelectedGt] = useState<string | null>(initialGtId ?? null)

  // FN 分析任务态（与原 PredictionsTab 相同：服务端化，切走切回可恢复）
  const [fnAdvice, setFnAdvice] = useState<Record<string, FnAdvice>>({})
  const [analyzingAll, setAnalyzingAll] = useState<{ done: number; total: number; current?: string | null } | null>(null)
  const [fnTaskId, setFnTaskId] = useState<string | null>(null)
  const [fnRunning, setFnRunning] = useState(false)
  const [fnAllError, setFnAllError] = useState<string | null>(null)

  const isVuln = datasetName.startsWith('vuln_')

  // 加载 predictions（vuln 数据集单 subset，固定取 default；失败/非 vuln 显示空态）
  useEffect(() => {
    if (!reportName || !datasetName) return
    const controller = new AbortController()
    const load = async () => {
      setLoading(true)
      setLoadError('')
      try {
        const res = await getPredictions(rootPath, reportName, datasetName, 'default', controller.signal)
        if (!controller.signal.aborted) setPredictions(res.predictions)
      } catch (e) {
        if (controller.signal.aborted || (isDomainError(e) && e.kind === 'aborted')) return
        setLoadError(e instanceof Error ? e.message : t('common.loadError'))
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }
    load()
    return () => controller.abort()
  }, [rootPath, reportName, datasetName, t])

  // FN 列表：全部 scan 的 missed gt 聚合去重（type 口径，与后端 extract_fn 一致）
  const fnGts = useMemo(() => {
    const map = new Map<string, FnGtRow>()
    for (const p of predictions) {
      if (!p.Findings) continue
      for (const g of p.Findings.gt) {
        if (g.missed && !map.has(g.gt_id)) map.set(g.gt_id, g)
      }
    }
    return [...map.values()]
  }, [predictions])

  // 初次进入：读已缓存结果 + 恢复进行中任务（多用户无状态，刷新可恢复）
  useEffect(() => {
    if (!isVuln || !reportName) return
    let cancelled = false
    getFnAdvice(rootPath, reportName, datasetName)
      .then((map) => { if (!cancelled && map) setFnAdvice(map) })
      .catch(() => {})
    getFnAdviceProgress(rootPath, reportName, datasetName)
      .then((p) => {
        if (cancelled || p.status !== 'running' || !p.task_id) return
        setFnTaskId(p.task_id)
        setFnRunning(true)
        setAnalyzingAll({ done: p.processed_count ?? 0, total: p.total_count ?? 0, current: p.current_gt_id })
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [rootPath, reportName, datasetName, isVuln])

  // 全量/单条分析统一走异步任务（单条传 gt_ids 子集）
  const onAnalyzeAll = useCallback(async (gtIds: string[]) => {
    if (!gtIds.length || fnRunning) return
    setFnAllError(null)
    const taskId = `fnadvice_${Date.now()}`
    setFnTaskId(taskId)
    setAnalyzingAll({ done: 0, total: gtIds.length, current: null })
    try {
      const res = await startFnAdviceTask(rootPath, reportName, datasetName, taskId, gtIds)
      if (res.status === 'error') {
        setFnAllError(res.error || '启动失败')
        setAnalyzingAll(null); setFnTaskId(null)
        return
      }
      setFnRunning(true)
    } catch (e) {
      console.error('fn-advice invoke failed:', e)
      setFnAllError(String(e))
      setAnalyzingAll(null); setFnTaskId(null)
    }
  }, [rootPath, reportName, datasetName, fnRunning])

  const progressFn = useCallback(async () => {
    return getFnAdviceProgress(rootPath, reportName, datasetName)
  }, [rootPath, reportName, datasetName])
  usePolling<FnAdviceProgress>({
    fn: progressFn,
    enabled: fnRunning,
    interval: 3000,
    onData: (p) => {
      setAnalyzingAll({ done: p.processed_count ?? 0, total: p.total_count ?? 0, current: p.current_gt_id })
      if (p.status === 'completed' || p.status === 'stopped' || p.status === 'error') {
        getFnAdvice(rootPath, reportName, datasetName).then(setFnAdvice).catch(() => {})
        setFnRunning(false)
        setFnTaskId(null)
        setAnalyzingAll((prev) => (prev ? { ...prev, current: null } : null))
        if (p.status === 'error' && p.error) setFnAllError(p.error)
      }
    },
  })

  const onStopFnAdvice = useCallback(async () => {
    if (!fnTaskId) return
    try { await stopFnAdviceTask(fnTaskId) } catch (e) { console.error(e) }
  }, [fnTaskId])

  // 选中 FN 的 advice（MCP staging 增量：分析中也可能已可读）
  const selGtObj = fnGts.find((g) => g.gt_id === selectedGt) ?? null
  const advice = selectedGt ? fnAdvice[selectedGt] : undefined
  // advice_structured.trace 来自 agent 输出（MCP/stdout 双通道），safeParse 容错：
  // 结构非法时仅隐藏时间线，不影响其余渲染
  const trace = useMemo(() => {
    const raw = (advice?.advice_structured as Record<string, unknown> | null | undefined)?.trace
    const res = fnTraceSchema.safeParse(raw)
    return res.success ? res.data : undefined
  }, [advice])
  const grouped = useMemo(() => groupFnTraceSteps(trace), [trace])

  const statusOf = (gtId: string): 'done' | 'failed' | 'running' | 'pending' => {
    if (fnRunning && analyzingAll?.current === gtId) return 'running'
    const adv = fnAdvice[gtId]
    if (!adv) return 'pending'
    return adv.status === 'ok' ? 'done' : 'failed'
  }

  if (!isVuln) {
    return <EmptyStateSystem reason="no-data" context={{ view: 'evaluations' }} />
  }

  return (
    <div className="flex flex-col gap-3">
      {loading && <Skeleton lines={4} />}
      {loadError && <ErrorAlert>{loadError}</ErrorAlert>}

      {!loading && (
        <>
          {/* 工具栏：全量分析 + 进度 + 停止 */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => onAnalyzeAll(fnGts.map((g) => g.gt_id))}
              disabled={!!fnRunning || fnGts.length === 0}
              className="px-3 py-1 text-sm rounded-[var(--radius-sm)] bg-[var(--accent)] text-[var(--bg)] hover:opacity-90 cursor-pointer disabled:opacity-50 disabled:cursor-wait transition-colors"
              title={t('vuln.analyzeAllTitle')}
            >
              {fnRunning ? t('vuln.analyzingAll') : t('vuln.analyzeAll', { n: fnGts.length })}
            </button>
            {fnRunning && analyzingAll && (
              <span className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
                <div className="h-1.5 w-24 rounded-full bg-[var(--border)] overflow-hidden">
                  <div className="h-full rounded-full bg-[var(--accent)] transition-all duration-300"
                       style={{ width: `${analyzingAll.total ? (analyzingAll.done / analyzingAll.total) * 100 : 0}%` }} />
                </div>
                <span className="tabular-nums whitespace-nowrap">
                  {analyzingAll.done}/{analyzingAll.total}{analyzingAll.current ? ` · ${analyzingAll.current}` : ''}
                </span>
              </span>
            )}
            {fnRunning && (
              <button onClick={onStopFnAdvice}
                className="px-2 py-1 text-xs rounded-[var(--radius-sm)] border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--danger)] hover:border-[var(--danger)] cursor-pointer transition-colors"
                title={t('vuln.stopTitle')}
              >{t('vuln.stop')}</button>
            )}
          </div>
          {fnAllError && (
            <div className="text-xs text-[var(--danger)] break-all">
              {t('vuln.fnAllErrorHint', { msg: fnAllError })}
            </div>
          )}

          {fnGts.length === 0 ? (
            <EmptyStateSystem reason="no-data" context={{ view: 'evaluations' }} />
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-3">
              {/* 左：FN 列表 + 状态徽标 */}
              <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] max-h-[70vh] overflow-y-auto">
                {fnGts.map((g) => {
                  const st = statusOf(g.gt_id)
                  return (
                    <button
                      key={g.gt_id}
                      onClick={() => setSelectedGt(g.gt_id)}
                      className={`w-full text-left px-3 py-2 border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-deep)] cursor-pointer transition-colors ${selectedGt === g.gt_id ? 'bg-[var(--bg-card2)]' : ''}`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-medium truncate">{g.gt_id}</span>
                        <StatusBadge status={st} />
                      </div>
                      <div className="text-xs text-[var(--text-muted)] truncate">
                        {g.vuln_type} · {g.location?.file}{g.location?.line ? `:${g.location.line}` : ''}
                      </div>
                    </button>
                  )
                })}
              </div>

              {/* 右：详情 */}
              <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] p-4 min-h-[200px] flex flex-col gap-3">
                {selGtObj ? (
                  <>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-base font-semibold">{selGtObj.gt_id}</h3>
                      <span className="text-xs px-2 py-0.5 rounded bg-[var(--danger)] text-white">{t('vuln.turingMissedFn')}</span>
                      <button
                        onClick={() => onAnalyzeAll([selGtObj.gt_id])}
                        disabled={fnRunning && analyzingAll?.current === selGtObj.gt_id}
                        className="ml-auto px-2.5 py-1 text-xs rounded-[var(--radius-sm)] bg-[var(--accent)] text-[var(--bg)] hover:opacity-90 cursor-pointer disabled:opacity-50 disabled:cursor-wait transition-colors"
                      >
                        {fnRunning && analyzingAll?.current === selGtObj.gt_id ? t('vuln.analyzing') : (advice ? t('vuln.reanalyze') : t('vuln.analyzeThis'))}
                      </button>
                    </div>
                    <div className="flex flex-col gap-1 text-sm">
                      <Detail label={t('vuln.type')} value={selGtObj.vuln_type} />
                      <Detail label={t('vuln.severity')} value={selGtObj.severity} />
                      <Detail label={t('vuln.cweId')} value={selGtObj.cwe} />
                      <Detail label={t('vuln.location')} value={`${selGtObj.location?.file || ''}${selGtObj.location?.line ? ':' + selGtObj.location.line : ''}`} />
                      {selGtObj.description && <Detail label={t('vuln.description')} value={selGtObj.description} />}
                    </div>

                    {/* 中断 banner：漏洞在哪一步中断导致漏挖 */}
                    {trace?.breakpoint && (
                      <div className="rounded-[var(--radius-sm)] border border-[var(--danger-border)] bg-[var(--danger-bg)] px-3 py-2 flex flex-col gap-1">
                        <div className="flex items-center gap-2 flex-wrap text-sm">
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--danger)] text-white font-semibold shrink-0">
                            {t('trace.breakpoint')}
                          </span>
                          <span>
                            {t('vuln.fnBreakpointAt', {
                              stage: TRACE_STAGE_LABEL_KEY[trace.breakpoint.stage]
                                ? t(TRACE_STAGE_LABEL_KEY[trace.breakpoint.stage]) : trace.breakpoint.stage,
                            })}
                          </span>
                          {trace.breakpoint.category && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded border border-[var(--danger-border)] text-[var(--danger)]">
                              {trace.breakpoint.category}
                            </span>
                          )}
                        </div>
                        {trace.breakpoint.reason && (
                          <p className="text-xs leading-relaxed break-words">{trace.breakpoint.reason}</p>
                        )}
                      </div>
                    )}

                    {/* agent 重构的中断轨迹时间线（无 trace：未分析或旧缓存） */}
                    {grouped ? (
                      <div className="flex flex-col gap-1">
                        <div className="text-xs text-[var(--text-muted)]">{t('trace.fnTraceTitle')}</div>
                        <TrajectoryView trajectory={grouped} breakpoint={trace?.breakpoint} />
                      </div>
                    ) : (
                      <div className="text-xs text-[var(--text-muted)]">
                        {advice ? t('vuln.fnNoTraceHint') : t('vuln.fnAdviceHint')}
                      </div>
                    )}

                    <FnAdviceCard advice={advice} />
                  </>
                ) : (
                  <div className="text-sm text-[var(--text-muted)]">{t('vuln.selectHint')}</div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: 'done' | 'failed' | 'running' | 'pending' }) {
  const { t } = useLocale()
  const key = { done: 'vuln.fnStatusDone', failed: 'vuln.fnStatusFailed', running: 'vuln.fnStatusRunning', pending: 'vuln.fnStatusPending' }[status]
  const cls = {
    done: 'bg-[var(--accent)] text-white',
    failed: 'bg-[var(--danger)] text-white',
    running: 'border border-[var(--accent)] text-[var(--accent)] animate-pulse',
    pending: 'border border-[var(--border)] text-[var(--text-muted)]',
  }[status]
  return <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 ${cls}`}>{t(key)}</span>
}

function Detail({ label, value }: { label: string; value?: string | null }) {
  if (value == null || value === '') return null
  return (
    <div className="text-sm">
      <span className="text-[var(--text-muted)] mr-2">{label}:</span>
      <span className="break-all">{String(value)}</span>
    </div>
  )
}
