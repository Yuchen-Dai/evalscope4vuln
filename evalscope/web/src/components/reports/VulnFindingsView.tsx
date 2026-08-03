/**
 * vuln_scan 漏洞浏览视图：按 GT 或 Finding 维度浏览，查看 GT↔finding 匹配关系 +
 * 图灵返回的漏洞详情。顶部「评分方式」selector 切换 类型+位置 / 仅位置 两套评分，
 * 选中后 summary/列表/详情都按该套展示。
 *
 * 数据来自 PredictionRow.Findings（后端 join findings_raw + score.metadata.vuln_match）。
 * f.type = 类型+位置，f.loc = 仅位置（老报告无 loc 则隐藏 selector、回退 type）。
 */
import { useMemo, useState, type ReactNode } from 'react'
import type { PredictionRow } from '@/api/types'

interface Props {
  predictions: PredictionRow[]
}

type ViewMode = 'gt' | 'finding'
type FilterKey = 'all' | 'TP' | 'FP' | 'FN'
type Regime = 'type' | 'loc'

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--danger)',
  HIGH: '#e8590c',
  MEDIUM: 'var(--accent)',
  MODERATE: 'var(--accent)',
  LOW: 'var(--text-muted)',
}

export default function VulnFindingsView({ predictions }: Props) {
  const vulnPreds = predictions.filter((p) => p.Findings)
  const [scanIdx, setScanIdx] = useState(0)
  const [regime, setRegime] = useState<Regime>('type')
  const [view, setView] = useState<ViewMode>('gt')
  const [filter, setFilter] = useState<FilterKey>('all')
  const [typeFilter, setTypeFilter] = useState('')
  const [selGt, setSelGt] = useState<string | null>(null)
  const [selFinding, setSelFinding] = useState<string | null>(null)
  const [showRaw, setShowRaw] = useState(false)

  const current = vulnPreds[Math.min(scanIdx, vulnPreds.length - 1)]
  const f = current?.Findings
  const hasLoc = !!f?.loc
  // 当前 regime 的 summary（loc 缺失回退 type）
  const summary = (regime === 'loc' && f?.loc?.summary ? f.loc.summary : (f?.type?.summary || f?.summary || {})) as Record<string, number>

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
  const pct = (k: string) => ((summary[k] ?? 0) * 100).toFixed(1) + '%'

  const Chip = ({ label, value, color }: { label: string; value: ReactNode; color?: string }) => (
    <div className="px-3 py-1.5 rounded-[var(--radius-sm)] bg-[var(--bg-card2)] border border-[var(--border)] text-xs">
      <span className="text-[var(--text-muted)]">{label} </span>
      <span className="font-mono font-medium" style={color ? { color } : undefined}>{value}</span>
    </div>
  )
  const selectClass = "px-2 py-1 text-sm rounded-[var(--radius-sm)] bg-[var(--bg-deep)] border border-[var(--border)] text-[var(--text)] hover:border-[var(--accent)] cursor-pointer transition-colors"

  return (
    <div className="flex flex-col gap-3">
      {/* summary chips（当前 regime） */}
      <div className="flex flex-wrap items-center gap-2">
        <Chip label="GT" value={summary.gt_total ?? f.gt.length} />
        <Chip label="findings" value={summary.findings_total ?? f.findings.length} />
        <Chip label="TP" value={summary.tp ?? 0} color="var(--accent)" />
        <Chip label="FP" value={summary.fp ?? 0} color="#e8590c" />
        <Chip label="FN" value={summary.fn ?? 0} color="var(--danger)" />
        <Chip label="P" value={pct('precision')} />
        <Chip label="R" value={pct('recall')} />
        <Chip label="F1" value={pct('f1')} />
      </div>

      {/* scan / 评分方式 / view / filter / type */}
      <div className="flex flex-wrap items-center gap-2">
        {vulnPreds.length > 1 && (
          <select value={scanIdx} onChange={(e) => { setScanIdx(Number(e.target.value)); setSelGt(null); setSelFinding(null) }} className={selectClass}>
            {vulnPreds.map((p, i) => <option key={i} value={i}>扫描 #{p.Index}</option>)}
          </select>
        )}
        {hasLoc && (
          <select value={regime} onChange={(e) => setRegime(e.target.value as Regime)} className={selectClass} aria-label="评分方式">
            <option value="type">评分方式：类型+位置</option>
            <option value="loc">评分方式：仅位置</option>
          </select>
        )}
        <div className="inline-flex rounded-[var(--radius)] border border-[var(--border-md)] overflow-hidden text-sm">
          {(['gt', 'finding'] as ViewMode[]).map((v) => (
            <button
              key={v}
              onClick={() => { setView(v); setSelGt(null); setSelFinding(null) }}
              className={`px-3 py-1 transition-colors cursor-pointer ${view === v ? 'bg-[var(--accent)] text-[var(--bg)] hover:opacity-90' : 'bg-[var(--bg-card2)] text-[var(--text-muted)] hover:bg-[var(--bg-deep)] hover:text-[var(--text)]'}`}
            >{v === 'gt' ? '按 GT' : '按 Finding'}</button>
          ))}
        </div>
        <div className="inline-flex rounded-[var(--radius)] border border-[var(--border-md)] overflow-hidden text-sm">
          {(['all', 'TP', 'FP', 'FN'] as FilterKey[]).map((k) => (
            <button
              key={k}
              onClick={() => setFilter(k)}
              className={`px-3 py-1 transition-colors cursor-pointer ${filter === k ? 'bg-[var(--accent)] text-[var(--bg)] hover:opacity-90' : 'bg-[var(--bg-card2)] text-[var(--text-muted)] hover:bg-[var(--bg-deep)] hover:text-[var(--text)]'}`}
            >{k === 'all' ? '全部' : k}</button>
          ))}
        </div>
        <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className={selectClass}>
          <option value="">所有类型</option>
          {typeOptions.map((tp) => <option key={tp} value={tp}>{tp}</option>)}
        </select>
      </div>

      {/* master / detail */}
      <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-3">
        <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] max-h-[70vh] overflow-y-auto">
          {view === 'gt' ? (
            gtList.length === 0 ? <div className="p-4 text-sm text-[var(--text-muted)]">无匹配 GT</div> :
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
                      ? <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--danger)] text-white">漏报</span>
                      : <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent)] text-white">{hits.length} 命中</span>}
                  </div>
                  <div className="text-xs text-[var(--text-muted)] truncate">{g.vuln_type} · {g.location?.file}{g.location?.line ? `:${g.location.line}` : ''}</div>
                </button>
              )
            })
          ) : (
            findingList.length === 0 ? <div className="p-4 text-sm text-[var(--text-muted)]">无 finding</div> :
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
              {findingList.length > 500 && <div className="p-2 text-xs text-[var(--text-muted)]">（仅显示前 500 条，用过滤缩小范围）</div>}
            </>
          )}
        </div>

        <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] p-4 min-h-[200px]">
          {view === 'gt' ? (
            selGtObj ? (
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-semibold">{selGtObj.gt_id}</h3>
                  {missedOf(selGtObj) && <span className="text-xs px-2 py-0.5 rounded bg-[var(--danger)] text-white">图灵漏报 FN</span>}
                </div>
                <Detail label="类型" value={selGtObj.vuln_type} />
                <Detail label="严重度" value={selGtObj.severity} color={sevColor(selGtObj.severity)} />
                <Detail label="CWE/ID" value={selGtObj.cwe} />
                <Detail label="位置" value={`${selGtObj.location?.file || ''}${selGtObj.location?.line ? ':' + selGtObj.location.line : ''}`} />
                {selGtObj.description && <Detail label="描述" value={selGtObj.description} />}
                <div className="mt-1">
                  <div className="text-xs text-[var(--text-muted)] mb-1">匹配的图灵 finding（{gtHitsOf(selGtObj).length}）</div>
                  {gtHitsOf(selGtObj).length === 0 ? (
                    <div className="text-sm text-[var(--text-muted)]">无 — 图灵未报出此漏洞</div>
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
                <Detail label="类型" value={selFindingObj.vuln_type} />
                <Detail label="严重度" value={selFindingObj.severity} color={sevColor(selFindingObj.severity)} />
                {selFindingObj.confidence != null && <Detail label="置信度" value={selFindingObj.confidence} />}
                {selFindingObj.validation_result && <Detail label="校验" value={selFindingObj.validation_result} />}
                <Detail label="命中 GT" value={gtIdOf(selFindingObj) || '无（FP，未命中任何 GT）'} color={gtIdOf(selFindingObj) ? 'var(--accent)' : 'var(--text-muted)'} />
                {selFindingObj.display_id && <Detail label="ID" value={selFindingObj.display_id} />}
                {selFindingObj.description && <Detail label="描述" value={selFindingObj.description} />}
                {selFindingObj.raw && (
                  <div className="mt-1">
                    <button onClick={() => setShowRaw(!showRaw)} className="text-xs text-[var(--accent)] hover:underline cursor-pointer">
                      图灵原始返回（raw JSON）{showRaw ? '▾' : '▸'}
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
  return <div className="text-sm text-[var(--text-muted)]">从左侧选择一项查看详情</div>
}
