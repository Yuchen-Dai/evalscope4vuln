/**
 * 漏洞结果对照视图（对比页 prediction tab 的 vuln_ 数据集形态）：
 * 左 gt（漏洞）列表（含各模型命中徽标）+ 选 gt → 右 N 列并排各模型命中该 gt
 * 的 finding 详情（紧凑卡片；漏报/无数据列显示空态）。
 * 数据由 PredictionTab 从已合并的 mergedPredictions 传入，本组件不重复拉取。
 * 复用 var(--compare-{i}-*) 品牌色槽位（最多 3 列，上游已 clamp）。
 */
import { useMemo, useState } from 'react'
import { useLocale } from '@/contexts/LocaleContext'
import type { PredictionRow } from '@/api/types'

/** 数据流端点（source/sink）：图灵形态 {type?, file?, line?, code?, description?}。 */
interface Endpoint {
  type?: string | null
  file?: string | null
  line?: number | null
  code?: string | null
  description?: string | null
}

/** 调用链一步：与 Endpoint 同形态（call_chain 可能是单 dict 或 list[dict]）。 */
type ChainStep = Endpoint

export interface VulnCompareModel {
  /** report 名（列标识） */
  name: string
  /** 表头显示名（displayLabels 优先） */
  label: string
  /** 该模型当前样本的 PredictionRow */
  row: PredictionRow | undefined
}

interface Props {
  models: VulnCompareModel[]
}

type Hit = 'tp' | 'fn' | '-'

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--danger)',
  HIGH: '#e8590c',
  MEDIUM: 'var(--accent)',
  MODERATE: 'var(--accent)',
  LOW: 'var(--text-muted)',
}

const HIT_COLOR: Record<Hit, string> = {
  tp: 'var(--success, #3fb950)',
  fn: 'var(--danger, #f85149)',
  '-': 'var(--text-muted)',
}

const HIT_MARK: Record<Hit, string> = { tp: '✓', fn: '✗', '-': '—' }

/** 端点形态收敛：JSON 字符串 → 解析；dict → 透传；其余 → null。 */
function asEndpoint(value: unknown): Endpoint | null {
  if (value == null) return null
  let obj: unknown = value
  if (typeof obj === 'string') {
    const s = obj.trim()
    if (!s || s[0] !== '{') return null
    try {
      obj = JSON.parse(s)
    } catch {
      return null
    }
  }
  if (typeof obj !== 'object' || Array.isArray(obj)) return null
  const o = obj as Record<string, unknown>
  if (o.file == null && o.line == null && o.code == null) return null
  return o as Endpoint
}

/** call_chain 形态收敛：JSON 字符串/dict → list[dict]；非法 → []。 */
function chainSteps(value: unknown): ChainStep[] {
  let obj: unknown = value
  if (typeof obj === 'string') {
    const s = obj.trim()
    if (!s || (s[0] !== '{' && s[0] !== '[')) return []
    try {
      obj = JSON.parse(s)
    } catch {
      return []
    }
  }
  if (obj == null) return []
  const arr = Array.isArray(obj) ? obj : [obj]
  return arr.filter(
    (it): it is ChainStep =>
      typeof it === 'object' && it != null && !Array.isArray(it),
  )
}

const fmtLoc = (e: { file?: string | null; line?: number | null }) =>
  `${e.file || '?'}${e.line != null ? ':' + e.line : ''}`

const sevColor = (s?: string | null) =>
  s ? (SEV_COLOR[s.toUpperCase()] || 'var(--text-muted)') : 'var(--text-muted)'

// ------------------------------------------------------------------ //
// Component                                                           //
// ------------------------------------------------------------------ //

export default function VulnFindingsCompareView({ models }: Props) {
  const { t } = useLocale()
  const [selectedGt, setSelectedGt] = useState<string | null>(null)

  // ── gt 列表：取第一个有 Findings.gt 的模型（GT 与模型无关，各模型一致）──
  const gtList = useMemo(() => {
    for (const m of models) {
      const gt = m.row?.Findings?.gt
      if (gt && gt.length) return gt
    }
    return []
  }, [models])

  // 渲染期回退（非 effect setState）：选中项不在列表（首载/数据集切换）时
  // 落到第一个 gt，用户点选后正常保持。
  const effectiveGt =
    selectedGt && gtList.some((g) => g.gt_id === selectedGt)
      ? selectedGt
      : (gtList[0]?.gt_id ?? null)

  // ── 命中矩阵：gt_id × model → tp/fn/- ─────────────────────────────
  const hits = useMemo(() => {
    const matrix: Record<string, Record<string, Hit>> = {}
    for (const g of gtList) {
      matrix[g.gt_id] = {}
      for (const m of models) {
        const item = m.row?.Findings?.gt.find((x) => x.gt_id === g.gt_id)
        if (item && (item.matched_finding_ids?.length ?? 0) > 0) matrix[g.gt_id][m.name] = 'tp'
        else if (item?.missed) matrix[g.gt_id][m.name] = 'fn'
        else matrix[g.gt_id][m.name] = '-'
      }
    }
    return matrix
  }, [gtList, models])

  const selGtObj = gtList.find((g) => g.gt_id === effectiveGt) ?? null

  if (!gtList.length) {
    return (
      <div className="text-sm text-[var(--text-muted)] p-4">
        {t('vuln.noGtData')}
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-3">
      {/* 左：gt 列表 */}
      <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] max-h-[75vh] overflow-y-auto">
        {gtList.map((g) => {
          const rowHits = hits[g.gt_id] || {}
          return (
            <button
              key={g.gt_id}
              onClick={() => setSelectedGt(g.gt_id)}
              className={`w-full text-left px-3 py-2 border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-deep)] cursor-pointer transition-colors ${
                effectiveGt === g.gt_id ? 'bg-[var(--bg-card2)]' : ''
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-mono text-[var(--text-muted)] truncate">{g.gt_id}</span>
                {g.severity && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent-dim)] text-[var(--accent)]">
                    {g.severity}
                  </span>
                )}
              </div>
              <div className="text-sm truncate" title={g.description || g.vuln_type || ''}>
                {g.description || g.vuln_type || t('vuln.noTitle')}
              </div>
              <div className="text-xs text-[var(--text-muted)] truncate">
                {g.vuln_type}
                {g.location?.file ? ` · ${g.location.file}${g.location.line != null ? ':' + g.location.line : ''}` : ''}
              </div>
              {/* 各模型命中徽标（品牌色描边） */}
              <div className="flex items-center gap-1 mt-1">
                {models.map((m, i) => (
                  <span
                    key={m.name}
                    className="text-[10px] px-1 rounded"
                    title={m.label}
                    style={{
                      color: HIT_COLOR[rowHits[m.name] ?? '-'],
                      border: `1px solid var(--compare-${i % 3}-border)`,
                    }}
                  >
                    {m.label.split('·')[0].trim().slice(0, 8)} {HIT_MARK[rowHits[m.name] ?? '-']}
                  </span>
                ))}
              </div>
            </button>
          )
        })}
      </div>

      {/* 右：N 列并排（sticky 列头） */}
      <div
        className="grid gap-3 min-w-0"
        style={{ gridTemplateColumns: `repeat(${models.length}, minmax(0, 1fr))` }}
      >
        {models.map((m, i) => {
          const hit = effectiveGt ? (hits[effectiveGt]?.[m.name] ?? '-') : '-'
          const matchedIds = m.row?.Findings?.gt
            .find((x) => x.gt_id === effectiveGt)
            ?.matched_finding_ids
          const findings = (matchedIds ?? [])
            .map((fid) => m.row?.Findings?.findings.find((f) => f.finding_id === fid))
            .filter((f): f is NonNullable<typeof f> => Boolean(f))
          return (
            <div
              key={m.name}
              className="rounded-[var(--radius)] border overflow-hidden flex flex-col bg-[var(--bg-card)]"
              style={{ borderColor: `var(--compare-${i % 3}-border)` }}
            >
              {/* 列头 */}
              <div
                className="sticky top-0 z-10 px-3 py-2 border-b text-sm font-semibold flex items-center justify-between gap-2"
                style={{
                  background: `var(--compare-${i % 3}-bg-header)`,
                  borderBottomColor: `var(--compare-${i % 3}-border)`,
                }}
              >
                <span className="truncate" title={m.label}>{m.label}</span>
                <span
                  className="text-xs px-1.5 py-0.5 rounded shrink-0 bg-[var(--bg-card)]"
                  style={{ color: HIT_COLOR[hit] }}
                >
                  {hit === 'tp' ? t('trace.statusTp') : hit === 'fn' ? t('trace.statusFn') : '—'}
                </span>
              </div>

              {/* finding 详情卡片 / 空态 */}
              <div className="p-2.5 max-h-[70vh] overflow-y-auto flex flex-col gap-2">
                {findings.length === 0 ? (
                  <div className="text-xs text-[var(--text-muted)] p-3 leading-relaxed">
                    {hit === 'fn'
                      ? t('trace.statusMissedHint')
                      : m.row?.Findings
                        ? t('vuln.noMatchedFinding')
                        : t('trace.noTraceData')}
                  </div>
                ) : (
                  findings.map((f) => (
                    <FindingCard key={f.finding_id ?? undefined} finding={f} />
                  ))
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* 选中 gt 的元信息条（类型/CWE/位置，与模型无关） */}
      {selGtObj && (
        <div className="lg:col-start-2 text-xs text-[var(--text-muted)] px-1">
          {t('vuln.type')}: {selGtObj.vuln_type || '—'}
          {selGtObj.cwe ? ` · ${t('vuln.cweId')}: ${selGtObj.cwe}` : ''}
          {selGtObj.location?.file
            ? ` · ${t('vuln.location')}: ${fmtLoc(selGtObj.location)}`
            : ''}
        </div>
      )}
    </div>
  )
}

// ------------------------------------------------------------------ //
// Finding detail card                                                 //
// ------------------------------------------------------------------ //

interface FindingLike {
  finding_id?: string | null
  display_id?: string | null
  vuln_type?: string | null
  severity?: string | null
  confidence?: number | null
  validation_result?: string | null
  title?: string | null
  description?: string | null
  classification?: 'TP' | 'FP' | null
  source?: unknown
  sink?: unknown
  call_chain?: unknown
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="text-xs">
      <span className="text-[var(--text-muted)] mr-1.5">{label}</span>
      <span className="break-all" title={value}>{value}</span>
    </div>
  )
}

function FindingCard({ finding }: { finding: FindingLike }) {
  const { t } = useLocale()
  const src = asEndpoint(finding.source)
  const snk = asEndpoint(finding.sink)
  const chain = chainSteps(finding.call_chain)
  return (
    <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-card2)] px-2.5 py-2 flex flex-col gap-1">
      {/* 标题 + 分类 */}
      <div className="flex items-start justify-between gap-2">
        <span className="text-xs font-medium break-all">
          {finding.title || finding.vuln_type || finding.display_id || finding.finding_id}
        </span>
        {finding.display_id && (
          <span className="text-[10px] font-mono text-[var(--text-muted)] shrink-0">
            {finding.display_id}
          </span>
        )}
      </div>
      {/* 类型 / 严重度 / 置信度 / 校验 */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs">
        <span>{finding.vuln_type || '—'}</span>
        <span style={{ color: sevColor(finding.severity) }}>{finding.severity || '—'}</span>
        {finding.confidence != null && (
          <span className="text-[var(--text-muted)]">
            {t('vuln.confidence')} {finding.confidence}
          </span>
        )}
        {finding.validation_result && (
          <span
            className="px-1 rounded"
            style={{
              color: finding.validation_result === 'CONFIRMED' ? 'var(--success, #3fb950)' : 'var(--text-muted)',
              background: 'var(--bg-deep)',
            }}
          >
            {finding.validation_result}
          </span>
        )}
      </div>
      {/* source / sink */}
      {src && <Field label={t('vuln.source')} value={fmtLoc(src)} />}
      {snk && <Field label={t('vuln.sink')} value={fmtLoc(snk)} />}
      {/* call_chain */}
      {chain.length > 0 && (
        <div className="text-xs">
          <span className="text-[var(--text-muted)] mr-1.5">{t('vuln.callChain')}</span>
          <span className="font-mono break-all" title={chain.map(fmtLoc).join(' → ')}>
            {chain.map(fmtLoc).join(' → ')}
          </span>
        </div>
      )}
      {finding.description && (
        <div className="text-xs text-[var(--text-muted)] line-clamp-3" title={finding.description}>
          {finding.description}
        </div>
      )}
    </div>
  )
}
