/**
 * vuln_scan 漏洞浏览视图：按 GT 或 Finding 维度浏览，查看 GT↔finding 匹配关系 +
 * 图灵返回的漏洞详情。regime（类型+位置/仅位置）由父组件（ReportDetailPage→PredictionsTab）
 * 通过 props 传入，本组件不自带 selector。
 */
import { useMemo, useState, type ReactNode } from 'react'
import { useLocale } from '@/contexts/LocaleContext'
import type { PredictionRow, FnAdvice } from '@/api/types'

interface Props {
  predictions: PredictionRow[]
  regime: 'type' | 'loc'
  /** FN 漏报 LLM 分析结果（gt_id → advice），由 PredictionsTab 加载/触发 */
  fnAdvice?: Record<string, FnAdvice>
  /** 正在分析的 gt_id 集合（单个按钮 loading） */
  analyzingGtIds?: Set<string>
  /** 全量分析进度（done/total/current_gt_id），null 表示未在批量分析 */
  analyzingAll?: { done: number; total: number; current?: string | null } | null
  /** 全量任务运行中（服务端任务态，切走切回可恢复） */
  fnRunning?: boolean
  /** 全量任务启动错误（如 judge 未配） */
  fnAllError?: string | null
  onAnalyze?: (gtId: string) => void
  onAnalyzeAll?: (gtIds: string[]) => void
  onStopFnAdvice?: () => void
}

type ViewMode = 'gt' | 'finding'
type FilterKey = 'all' | 'TP' | 'FP' | 'FN'

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--danger)',
  HIGH: '#e8590c',
  MEDIUM: 'var(--accent)',
  MODERATE: 'var(--accent)',
  LOW: 'var(--text-muted)',
}

export default function VulnFindingsView({
  predictions, regime, fnAdvice, analyzingGtIds, analyzingAll, fnRunning, fnAllError, onAnalyze, onAnalyzeAll, onStopFnAdvice,
}: Props) {
  const { t } = useLocale()
  const vulnPreds = predictions.filter((p) => p.Findings)
  const [scanIdx, setScanIdx] = useState(0)
  const [view, setView] = useState<ViewMode>('gt')
  const [filter, setFilter] = useState<FilterKey>('all')
  const [typeFilter, setTypeFilter] = useState('')
  const [selGt, setSelGt] = useState<string | null>(null)
  const [selFinding, setSelFinding] = useState<string | null>(null)
  const [showRaw, setShowRaw] = useState(false)

  const current = vulnPreds[Math.min(scanIdx, vulnPreds.length - 1)]
  const f = current?.Findings
  const summary = ((regime === 'loc' && f?.loc?.summary) ? f.loc.summary : (f?.type?.summary || f?.summary || {})) as Record<string, number>
  const scoreVal = (current?.Score?.value || {}) as Record<string, number>
  const overallPrefix = regime === 'loc' ? 'LocOnly/Overall/' : 'Overall/'

  // 按 regime 取分类/命中（loc 字段缺失回退 type 字段）
  const classOf = (it: { classification?: string | null; classification_loc?: string | null }) =>
    regime === 'type' ? (it.classification ?? 'FP') : (it.classification_loc ?? it.classification ?? 'FP')
  const gtHitsOf = (g: { matched_finding_ids?: string[]; matched_finding_ids_loc?: string[] }) =>
    regime === 'type' ? (g.matched_finding_ids ?? []) : (g.matched_finding_ids_loc ?? g.matched_finding_ids ?? [])
  const gtIdOf = (it: { gt_id?: string | null; gt_id_loc?: string | null }) =>
    regime === 'type' ? it.gt_id : (it.gt_id_loc ?? it.gt_id)
  const missedOf = (g: { missed?: boolean; missed_loc?: boolean }) =>
    regime === 'type' ? g.missed : (g.missed_loc ?? g.missed)

  const typeOptions = useMemo(() => {
    const s = new Set<string>()
    f?.gt.forEach((g) => g.vuln_type && s.add(g.vuln_type))
    f?.findings.forEach((it) => it.vuln_type && s.add(it.vuln_type))
    return [...s].sort()
  }, [f])

  // 漏报(FN)的 gt_id 列表（missedOf 按 regime 取），供「全量分析漏报」
  const fnGtIds = useMemo(
    () => (f?.gt.filter((g) => missedOf(g)).map((g) => g.gt_id)) ?? [],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [f, regime],
  )

  const gtList = useMemo(() => {
    if (!f) return []
    return f.gt.filter((g) => {
      if (filter === 'TP' && gtHitsOf(g).length === 0) return false
      if (filter === 'FN' && !missedOf(g)) return false
      if (typeFilter && g.vuln_type !== typeFilter) return false
      return true
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [f, filter, typeFilter, regime])

  const findingList = useMemo(() => {
    if (!f) return []
    return f.findings.filter((it) => {
      if (filter === 'TP' && classOf(it) !== 'TP') return false
      if (filter === 'FP' && classOf(it) !== 'FP') return false
      if (typeFilter && it.vuln_type !== typeFilter) return false
      return true
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [f, filter, typeFilter, regime])

  if (!f) return null

  const selGtObj = f.gt.find((g) => g.gt_id === selGt)
  const selFindingObj = f.findings.find((it) => it.finding_id === selFinding)
  const sevColor = (s?: string | null) => (s ? SEV_COLOR[s.toUpperCase()] || 'var(--text-muted)' : 'var(--text-muted)')
  const pct = (key: string) => ((scoreVal[overallPrefix + key] ?? 0) * 100).toFixed(1) + '%'

  const Chip = ({ label, value, color }: { label: string; value: ReactNode; color?: string }) => (
    <div className="px-3 py-1.5 rounded-[var(--radius-sm)] bg-[var(--bg-card2)] border border-[var(--border)] text-xs">
      <span className="text-[var(--text-muted)]">{label} </span>
      <span className="font-mono font-medium" style={color ? { color } : undefined}>{value}</span>
    </div>
  )

  return (
    <div className="flex flex-col gap-3">
      {/* summary chips */}
      <div className="flex flex-wrap items-center gap-2">
        <Chip label={t('vuln.gt')} value={summary.gt_total ?? f.gt.length} />
        <Chip label={t('vuln.findings')} value={summary.findings_total ?? f.findings.length} />
        <Chip label={t('vuln.tp')} value={summary.tp ?? 0} color="var(--accent)" />
        <Chip label={t('vuln.fp')} value={summary.fp ?? 0} color="#e8590c" />
        <Chip label={t('vuln.fn')} value={summary.fn ?? 0} color="var(--danger)" />
        <Chip label={t('vuln.precisionShort')} value={pct('Precision')} />
        <Chip label={t('vuln.recallShort')} value={pct('Recall')} />
        <Chip label={t('vuln.f1Short')} value={pct('F1')} />
      </div>

      {/* scan / view / filter / type */}
      <div className="flex flex-wrap items-center gap-2">
        {vulnPreds.length > 1 && (
          <select
            value={scanIdx}
            onChange={(e) => { setScanIdx(Number(e.target.value)); setSelGt(null); setSelFinding(null) }}
            className="px-2 py-1 text-sm rounded-[var(--radius-sm)] bg-[var(--bg-deep)] border border-[var(--border)] text-[var(--text)] hover:border-[var(--accent)] cursor-pointer transition-colors"
          >
            {vulnPreds.map((p, i) => <option key={i} value={i}>{t('vuln.scanNumber', { n: p.Index })}</option>)}
          </select>
        )}
        <div className="inline-flex rounded-[var(--radius)] border border-[var(--border-md)] overflow-hidden text-sm">
          {(['gt', 'finding'] as ViewMode[]).map((v) => (
            <button
              key={v}
              onClick={() => { setView(v); setSelGt(null); setSelFinding(null) }}
              className={`px-3 py-1 transition-colors cursor-pointer ${view === v ? 'bg-[var(--accent)] text-[var(--bg)] hover:opacity-90' : 'bg-[var(--bg-card2)] text-[var(--text-muted)] hover:bg-[var(--bg-deep)] hover:text-[var(--text)]'}`}
            >{v === 'gt' ? t('vuln.byGt') : t('vuln.byFinding')}</button>
          ))}
        </div>
        <div className="inline-flex rounded-[var(--radius)] border border-[var(--border-md)] overflow-hidden text-sm">
          {(['all', 'TP', 'FP', 'FN'] as FilterKey[]).map((k) => (
            <button
              key={k}
              onClick={() => setFilter(k)}
              className={`px-3 py-1 transition-colors cursor-pointer ${filter === k ? 'bg-[var(--accent)] text-[var(--bg)] hover:opacity-90' : 'bg-[var(--bg-card2)] text-[var(--text-muted)] hover:bg-[var(--bg-deep)] hover:text-[var(--text)]'}`}
            >{k === 'all' ? t('vuln.all') : k}</button>
          ))}
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="px-2 py-1 text-sm rounded-[var(--radius-sm)] bg-[var(--bg-deep)] border border-[var(--border)] text-[var(--text)] hover:border-[var(--accent)] cursor-pointer transition-colors"
        >
          <option value="">{t('vuln.allTypes')}</option>
          {typeOptions.map((tp) => <option key={tp} value={tp}>{tp}</option>)}
        </select>
        {onAnalyzeAll && fnGtIds.length > 0 && (
          <div className="flex items-center gap-2 ml-auto">
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
            {fnRunning && onStopFnAdvice && (
              <button onClick={onStopFnAdvice}
                className="px-2 py-1 text-xs rounded-[var(--radius-sm)] border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--danger)] hover:border-[var(--danger)] cursor-pointer transition-colors"
                title={t('vuln.stopTitle')}
              >{t('vuln.stop')}</button>
            )}
            <button
              onClick={() => onAnalyzeAll(fnGtIds)}
              disabled={!!fnRunning}
              className="px-3 py-1 text-sm rounded-[var(--radius-sm)] bg-[var(--accent)] text-[var(--bg)] hover:opacity-90 cursor-pointer disabled:opacity-50 disabled:cursor-wait transition-colors"
              title={t('vuln.analyzeAllTitle')}
            >
              {fnRunning ? t('vuln.analyzingAll') : t('vuln.analyzeAll', { n: fnGtIds.length })}
            </button>
          </div>
        )}
      </div>
      {fnAllError && (
        <div className="text-xs text-[var(--danger)] break-all">
          {t('vuln.fnAllErrorHint', { msg: fnAllError })}
        </div>
      )}

      {/* master / detail */}
      <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-3">
        {/* 左列表 */}
        <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] max-h-[70vh] overflow-y-auto">
          {view === 'gt' ? (
            gtList.length === 0 ? <div className="p-4 text-sm text-[var(--text-muted)]">{t('vuln.noMatchingGt')}</div> :
            gtList.map((g) => {
              const hits = gtHitsOf(g)
              const miss = missedOf(g)
              return (
                <button
                  key={g.gt_id}
                  onClick={() => { setSelGt(g.gt_id); setSelFinding(null); setShowRaw(false) }}
                  className={`w-full text-left px-3 py-2 border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-deep)] cursor-pointer transition-colors ${selGt === g.gt_id ? 'bg-[var(--bg-card2)]' : ''}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium truncate">{g.gt_id}</span>
                    {miss
                      ? <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--danger)] text-white">{t('vuln.missed')}</span>
                      : <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent)] text-white">{t('vuln.nHits', { n: hits.length })}</span>}
                  </div>
                  <div className="text-xs text-[var(--text-muted)] truncate">{g.vuln_type} · {g.location?.file}{g.location?.line ? `:${g.location.line}` : ''}</div>
                </button>
              )
            })
          ) : (
            findingList.length === 0 ? <div className="p-4 text-sm text-[var(--text-muted)]">{t('vuln.noFinding')}</div> :
            <>
              {findingList.slice(0, 500).map((it) => {
                const cls = classOf(it)
                return (
                  <button
                    key={it.finding_id}
                    onClick={() => { setSelFinding(it.finding_id ?? null); setSelGt(null); setShowRaw(false) }}
                    className={`w-full text-left px-3 py-2 border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-deep)] cursor-pointer transition-colors ${selFinding === it.finding_id ? 'bg-[var(--bg-card2)]' : ''}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs text-[var(--text-muted)] truncate">{it.display_id || it.finding_id}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${cls === 'TP' ? 'bg-[var(--accent)] text-white' : 'bg-[var(--bg-deep)] text-[var(--text-muted)]'}`}>{cls}</span>
                    </div>
                    <div className="text-sm truncate">{it.title || it.vuln_type}</div>
                    <div className="text-xs" style={{ color: sevColor(it.severity) }}>{it.vuln_type} · {it.severity}</div>
                  </button>
                )
              })}
              {findingList.length > 500 && <div className="p-2 text-xs text-[var(--text-muted)]">{t('vuln.showingFirst')}</div>}
            </>
          )}
        </div>

        {/* 右详情 */}
        <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] p-4 min-h-[200px]">
          {view === 'gt' ? (
            selGtObj ? (
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-semibold">{selGtObj.gt_id}</h3>
                  {missedOf(selGtObj) && <span className="text-xs px-2 py-0.5 rounded bg-[var(--danger)] text-white">{t('vuln.turingMissedFn')}</span>}
                </div>
                {missedOf(selGtObj) && onAnalyze && (
                  <FnAdviceBlock
                    gtId={selGtObj.gt_id}
                    advice={fnAdvice?.[selGtObj.gt_id]}
                    analyzing={analyzingGtIds?.has(selGtObj.gt_id)}
                    onAnalyze={onAnalyze}
                  />
                )}
                <Detail label={t('vuln.type')} value={selGtObj.vuln_type} />
                <Detail label={t('vuln.severity')} value={selGtObj.severity} color={sevColor(selGtObj.severity)} />
                <Detail label={t('vuln.cweId')} value={selGtObj.cwe} />
                <Detail label={t('vuln.location')} value={`${selGtObj.location?.file || ''}${selGtObj.location?.line ? ':' + selGtObj.location.line : ''}`} />
                {selGtObj.description && <Detail label={t('vuln.description')} value={selGtObj.description} />}
                <div className="mt-1">
                  <div className="text-xs text-[var(--text-muted)] mb-1">{t('vuln.matchedFindings', { n: gtHitsOf(selGtObj).length })}</div>
                  {gtHitsOf(selGtObj).length === 0 ? (
                    <div className="text-sm text-[var(--text-muted)]">{t('vuln.noMatchedFinding')}</div>
                  ) : (
                    gtHitsOf(selGtObj).map((fid) => {
                      const ff = f.findings.find((x) => x.finding_id === fid)
                      return (
                        <button
                          key={fid}
                          onClick={() => { setView('finding'); setSelFinding(fid); setSelGt(null); setShowRaw(false) }}
                          className="block w-full text-left px-3 py-2 mb-1 rounded-[var(--radius-sm)] bg-[var(--bg-card2)] hover:border-[var(--accent)] border border-transparent cursor-pointer transition-colors"
                        >
                          <div className="text-sm">{ff?.title || ff?.vuln_type || fid}</div>
                          <div className="text-xs text-[var(--text-muted)]">{ff?.vuln_type} · {ff?.severity} · {ff?.display_id || fid}</div>
                        </button>
                      )
                    })
                  )}
                </div>
              </div>
            ) : <EmptyDetail />
          ) : (
            selFindingObj ? (
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-semibold truncate">{selFindingObj.title || selFindingObj.vuln_type || selFindingObj.finding_id}</h3>
                  <span className={`text-xs px-2 py-0.5 rounded shrink-0 ${classOf(selFindingObj) === 'TP' ? 'bg-[var(--accent)] text-white' : 'bg-[var(--bg-deep)] text-[var(--text-muted)]'}`}>{classOf(selFindingObj)}</span>
                </div>
                <Detail label={t('vuln.type')} value={selFindingObj.vuln_type} />
                <Detail label={t('vuln.severity')} value={selFindingObj.severity} color={sevColor(selFindingObj.severity)} />
                {selFindingObj.confidence != null && <Detail label={t('vuln.confidence')} value={selFindingObj.confidence} />}
                {selFindingObj.validation_result && <Detail label={t('vuln.validation')} value={selFindingObj.validation_result} />}
                <Detail label={t('vuln.hitGt')} value={gtIdOf(selFindingObj) || t('vuln.fpNoHit')} color={gtIdOf(selFindingObj) ? 'var(--accent)' : 'var(--text-muted)'} />
                {selFindingObj.display_id && <Detail label={t('vuln.id')} value={selFindingObj.display_id} />}
                {selFindingObj.description && <Detail label={t('vuln.description')} value={selFindingObj.description} />}
                {selFindingObj.raw && (
                  <div className="mt-1">
                    <button onClick={() => setShowRaw(!showRaw)} className="text-xs text-[var(--accent)] hover:underline cursor-pointer">
                      {t('vuln.rawJson')}{showRaw ? '▾' : '▸'}
                    </button>
                    {showRaw && (
                      <pre className="mt-1 p-3 rounded-[var(--radius-sm)] bg-[var(--bg-deep)] text-xs overflow-x-auto max-h-[400px] overflow-y-auto">{JSON.stringify(selFindingObj.raw, null, 2)}</pre>
                    )}
                  </div>
                )}
              </div>
            ) : <EmptyDetail />
          )}
        </div>
      </div>
    </div>
  )
}

function Detail({ label, value, color }: { label: string; value?: ReactNode; color?: string }) {
  if (value == null || value === '') return null
  return (
    <div className="text-sm">
      <span className="text-[var(--text-muted)] mr-2">{label}:</span>
      <span style={color ? { color } : undefined} className="break-all">{String(value)}</span>
    </div>
  )
}

function EmptyDetail() {
  const { t } = useLocale()
  return <div className="text-sm text-[var(--text-muted)]">{t('vuln.selectHint')}</div>
}

/** FN 漏报 LLM 分析建议区块：触发按钮 + 建议/错误展示。 */
function FnAdviceBlock({ gtId, advice, analyzing, onAnalyze }: {
  gtId: string
  advice?: FnAdvice
  analyzing?: boolean
  onAnalyze?: (gtId: string) => void
}) {
  const { t } = useLocale()
  return (
    <div className="mt-1 pt-2 border-t border-[var(--border)]">
      <div className="flex items-center gap-2 mb-1">
        <button
          onClick={() => onAnalyze?.(gtId)}
          disabled={analyzing}
          className="px-2.5 py-1 text-xs rounded-[var(--radius-sm)] bg-[var(--accent)] text-[var(--bg)] hover:opacity-90 cursor-pointer disabled:opacity-50 disabled:cursor-wait transition-colors"
        >
          {analyzing ? t('vuln.analyzing') : (advice ? t('vuln.reanalyze') : t('vuln.analyzeMissed'))}
        </button>
        {advice?.status === 'ok' && advice.related_sessions != null && (
          <span className="text-[10px] text-[var(--text-muted)]">
            {t('vuln.fnRelatedSessions', { sessions: advice.related_sessions, files: advice.related_files?.length ?? 0 })}
          </span>
        )}
      </div>
      {!advice && (
        <div className="text-xs text-[var(--text-muted)]">
          {t('vuln.fnAdviceHint')}
        </div>
      )}
      {advice?.status === 'error' && (
        <div className="text-xs text-[var(--danger)] break-all">⚠ {advice.error}</div>
      )}
      {advice?.status === 'ok' && advice.advice && (
        <pre className="mt-1 p-3 rounded-[var(--radius-sm)] bg-[var(--bg-deep)] text-xs whitespace-pre-wrap break-words max-h-[400px] overflow-y-auto">{advice.advice}</pre>
      )}
    </div>
  )
}
