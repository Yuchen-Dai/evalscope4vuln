/**
 * vuln_scan 漏洞浏览视图：按 GT 或 Finding 维度浏览，查看 GT↔finding 匹配关系 +
 * 图灵返回的漏洞详情（type/severity/source/sink/raw）。
 *
 * 数据来自 PredictionRow.Findings（后端 join findings_raw + score.metadata.vuln_match）。
 */
import { useMemo, useState, type ReactNode } from 'react'
import type { PredictionRow } from '@/api/types'

interface Props {
  predictions: PredictionRow[]
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

export default function VulnFindingsView({ predictions }: Props) {
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
  const summary = (f?.summary || {}) as Record<string, number>
  const scoreVal = (current?.Score?.value || {}) as Record<string, number>

  const typeOptions = useMemo(() => {
    const s = new Set<string>()
    f?.gt.forEach((g) => g.vuln_type && s.add(g.vuln_type))
    f?.findings.forEach((it) => it.vuln_type && s.add(it.vuln_type))
    return [...s].sort()
  }, [f])

  const gtList = useMemo(() => {
    if (!f) return []
    return f.gt.filter((g) => {
      if (filter === 'TP' && !(g.matched_finding_ids?.length)) return false
      if (filter === 'FN' && !g.missed) return false
      if (typeFilter && g.vuln_type !== typeFilter) return false
      return true
    })
  }, [f, filter, typeFilter])

  const findingList = useMemo(() => {
    if (!f) return []
    return f.findings.filter((it) => {
      if (filter === 'TP' && it.classification !== 'TP') return false
      if (filter === 'FP' && it.classification !== 'FP') return false
      if (typeFilter && it.vuln_type !== typeFilter) return false
      return true
    })
  }, [f, filter, typeFilter])

  if (!f) return null

  const selGtObj = f.gt.find((g) => g.gt_id === selGt)
  const selFindingObj = f.findings.find((it) => it.finding_id === selFinding)
  const sevColor = (s?: string | null) => (s ? SEV_COLOR[s.toUpperCase()] || 'var(--text-muted)' : 'var(--text-muted)')
  const pct = (k: string) => ((scoreVal[k] ?? 0) * 100).toFixed(1) + '%'

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
        <Chip label="GT" value={summary.gt_total ?? f.gt.length} />
        <Chip label="findings" value={summary.findings_total ?? f.findings.length} />
        <Chip label="TP" value={summary.tp ?? 0} color="var(--accent)" />
        <Chip label="FP" value={summary.fp ?? 0} color="#e8590c" />
        <Chip label="FN" value={summary.fn ?? 0} color="var(--danger)" />
        <Chip label="P" value={pct('Overall/Precision')} />
        <Chip label="R" value={pct('Overall/Recall')} />
        <Chip label="F1" value={pct('Overall/F1')} />
      </div>

      {/* scan / view / filter / type */}
      <div className="flex flex-wrap items-center gap-2">
        {vulnPreds.length > 1 && (
          <select
            value={scanIdx}
            onChange={(e) => { setScanIdx(Number(e.target.value)); setSelGt(null); setSelFinding(null) }}
            className="px-2 py-1 text-sm rounded-[var(--radius-sm)] bg-[var(--bg-deep)] border border-[var(--border)] text-[var(--text)] hover:border-[var(--accent)] cursor-pointer transition-colors"
          >
            {vulnPreds.map((p, i) => <option key={i} value={i}>扫描 #{p.Index}</option>)}
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
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="px-2 py-1 text-sm rounded-[var(--radius-sm)] bg-[var(--bg-deep)] border border-[var(--border)] text-[var(--text)] hover:border-[var(--accent)] cursor-pointer transition-colors"
        >
          <option value="">所有类型</option>
          {typeOptions.map((tp) => <option key={tp} value={tp}>{tp}</option>)}
        </select>
      </div>

      {/* master / detail */}
      <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-3">
        {/* 左列表 */}
        <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] max-h-[70vh] overflow-y-auto">
          {view === 'gt' ? (
            gtList.length === 0 ? <div className="p-4 text-sm text-[var(--text-muted)]">无匹配 GT</div> :
            gtList.map((g) => (
              <button
                key={g.gt_id}
                onClick={() => { setSelGt(g.gt_id); setSelFinding(null); setShowRaw(false) }}
                className={`w-full text-left px-3 py-2 border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-deep)] cursor-pointer transition-colors ${selGt === g.gt_id ? 'bg-[var(--bg-card2)]' : ''}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium truncate">{g.gt_id}</span>
                  {g.missed
                    ? <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--danger)] text-white">漏报</span>
                    : <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent)] text-white">{g.matched_finding_ids?.length || 0} 命中</span>}
                </div>
                <div className="text-xs text-[var(--text-muted)] truncate">{g.vuln_type} · {g.location?.file}{g.location?.line ? `:${g.location.line}` : ''}</div>
              </button>
            ))
          ) : (
            findingList.length === 0 ? <div className="p-4 text-sm text-[var(--text-muted)]">无 finding</div> :
            <>
              {findingList.slice(0, 500).map((it) => (
                <button
                  key={it.finding_id}
                  onClick={() => { setSelFinding(it.finding_id ?? null); setSelGt(null); setShowRaw(false) }}
                  className={`w-full text-left px-3 py-2 border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-deep)] cursor-pointer transition-colors ${selFinding === it.finding_id ? 'bg-[var(--bg-card2)]' : ''}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs text-[var(--text-muted)] truncate">{it.display_id || it.finding_id}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${it.classification === 'TP' ? 'bg-[var(--accent)] text-white' : 'bg-[var(--bg-deep)] text-[var(--text-muted)]'}`}>{it.classification}</span>
                  </div>
                  <div className="text-sm truncate">{it.title || it.vuln_type}</div>
                  <div className="text-xs" style={{ color: sevColor(it.severity) }}>{it.vuln_type} · {it.severity}</div>
                </button>
              ))}
              {findingList.length > 500 && <div className="p-2 text-xs text-[var(--text-muted)]">（仅显示前 500 条，用过滤缩小范围）</div>}
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
                  {selGtObj.missed && <span className="text-xs px-2 py-0.5 rounded bg-[var(--danger)] text-white">图灵漏报 FN</span>}
                </div>
                <Detail label="类型" value={selGtObj.vuln_type} />
                <Detail label="严重度" value={selGtObj.severity} color={sevColor(selGtObj.severity)} />
                <Detail label="CWE/ID" value={selGtObj.cwe} />
                <Detail label="位置" value={`${selGtObj.location?.file || ''}${selGtObj.location?.line ? ':' + selGtObj.location.line : ''}`} />
                {selGtObj.description && <Detail label="描述" value={selGtObj.description} />}
                <div className="mt-1">
                  <div className="text-xs text-[var(--text-muted)] mb-1">匹配的图灵 finding（{selGtObj.matched_finding_ids?.length || 0}）</div>
                  {(selGtObj.matched_finding_ids?.length || 0) === 0 ? (
                    <div className="text-sm text-[var(--text-muted)]">无 — 图灵未报出此漏洞</div>
                  ) : (
                    selGtObj.matched_finding_ids?.map((fid) => {
                      const ff = f.findings.find((x) => x.finding_id === fid)
                      return (
                        <button
                          key={fid}
                          onClick={() => { setView('finding'); setSelFinding(fid); setSelGt(null); setShowRaw(false) }}
                          className="block w-full text-left px-3 py-2 mb-1 rounded-[var(--radius-sm)] bg-[var(--bg-card2)] hover:border-[var(--accent)] border border-transparent"
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
                  <span className={`text-xs px-2 py-0.5 rounded shrink-0 ${selFindingObj.classification === 'TP' ? 'bg-[var(--accent)] text-white' : 'bg-[var(--bg-deep)] text-[var(--text-muted)]'}`}>{selFindingObj.classification}</span>
                </div>
                <Detail label="类型" value={selFindingObj.vuln_type} />
                <Detail label="严重度" value={selFindingObj.severity} color={sevColor(selFindingObj.severity)} />
                {selFindingObj.confidence != null && <Detail label="置信度" value={selFindingObj.confidence} />}
                {selFindingObj.validation_result && <Detail label="校验" value={selFindingObj.validation_result} />}
                <Detail label="命中 GT" value={selFindingObj.gt_id || '无（FP，未命中任何 GT）'} color={selFindingObj.gt_id ? 'var(--accent)' : 'var(--text-muted)'} />
                {selFindingObj.display_id && <Detail label="ID" value={selFindingObj.display_id} />}
                {selFindingObj.description && <Detail label="描述" value={selFindingObj.description} />}
                {selFindingObj.raw && (
                  <div className="mt-1">
                    <button onClick={() => setShowRaw(!showRaw)} className="text-xs text-[var(--accent)] hover:underline">
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
