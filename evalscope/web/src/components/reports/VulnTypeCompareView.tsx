/**
 * 按类型对比视图（对比页第 4 tab）：行 = vuln_type（各模型 buckets 的并集），
 * 列 = 各模型，格 = 该模型该类型的 Precision/Recall/F1/TP/FP/FN；
 * 末尾合计行取各模型 Findings.type.summary（缺则 buckets 汇总）。
 * 数据从已加载的 mergedPredictions 取（ComparePage 传入），不重复拉取。
 * 比率列用 scoreColor 着色（同分数表口径）。
 */
import { useMemo } from 'react'
import { useLocale } from '@/contexts/LocaleContext'
import { scoreColor } from '@/utils/colorScale'
import { formatScore } from '@/domain/metric/registry'
import type { PredictionRow } from '@/api/types'

export interface VulnTypeModel {
  /** report 名（列标识） */
  name: string
  /** 表头显示名（displayLabels 优先） */
  label: string
  /** 该模型当前样本的 PredictionRow（vuln 单样本报告仅一行） */
  row: PredictionRow | undefined
}

interface Props {
  models: VulnTypeModel[]
}

/** bucket 的运行时形态（schema 侧是 record<string, unknown>）。 */
interface Bucket {
  vuln_type?: string | null
  tp?: number | null
  fp?: number | null
  fn?: number | null
  precision?: number | null
  recall?: number | null
  f1?: number | null
  gt_total?: number | null
  found?: number | null
}

const num = (v: unknown): number | null =>
  typeof v === 'number' && Number.isFinite(v) ? v : null

const bucketsOf = (row: PredictionRow | undefined): Bucket[] => {
  const raw = row?.Findings?.type?.buckets
  if (!Array.isArray(raw)) return []
  return raw as Bucket[]
}

const summaryOf = (row: PredictionRow | undefined): Record<string, unknown> =>
  (row?.Findings?.type?.summary as Record<string, unknown>) || {}

const count = (v: number | null): string => (v == null ? '—' : String(v))

/** 比率单元格：走 metric registry 格式化 + scoreColor 着色（与对比分数表一致）。 */
function RatioCell({ metric, value, t }: { metric: string; value: number | null; t: (p: string) => string }) {
  if (value == null) {
    return <span className="text-[var(--text-dim)]">—</span>
  }
  return (
    <span
      className="px-1.5 py-0.5 rounded-[var(--radius-xs)] font-mono tabular-nums"
      style={{ color: scoreColor(value) }}
      title={t(`metrics.${metric}`)}
    >
      {formatScore(metric, value, t)}
    </span>
  )
}

export default function VulnTypeCompareView({ models }: Props) {
  const { t } = useLocale()

  // 各模型 bucket 映射 + 类型并集（保持出现顺序， Overall 类伪桶排除在外：
  // buckets 只含 vuln_type 桶，overall 在 summary）
  const { byModel, allTypes, hasAnyData } = useMemo(() => {
    const byModel = new Map<string, Bucket[]>()
    const typeSet = new Set<string>()
    let hasAnyData = false
    for (const m of models) {
      const buckets = bucketsOf(m.row)
      byModel.set(m.name, buckets)
      if (buckets.length) hasAnyData = true
      for (const b of buckets) {
        if (b.vuln_type) typeSet.add(b.vuln_type)
      }
    }
    return { byModel, allTypes: [...typeSet].sort(), hasAnyData }
  }, [models])

  if (!hasAnyData) {
    return (
      <div className="text-sm text-[var(--text-muted)] p-4">
        {t('vuln.noTypeBuckets')}
      </div>
    )
  }

  return (
    <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[var(--border)]">
            <th className="text-left px-3 py-2 text-xs text-[var(--text-muted)] font-medium whitespace-nowrap sticky left-0 bg-[var(--bg-card)] z-10">
              {t('vuln.type')}
            </th>
            {models.map((m, i) => (
              <th
                key={m.name}
                colSpan={6}
                className="text-center px-3 py-2 text-xs font-semibold whitespace-nowrap border-l border-[var(--border)]"
                style={{ color: `var(--compare-${i % 3}-dot)` }}
                title={m.label}
              >
                {m.label}
              </th>
            ))}
          </tr>
          {/* 子表头：每模型 P/R/F1/TP/FP/FN */}
          <tr className="border-b border-[var(--border)]">
            <th className="sticky left-0 bg-[var(--bg-card)] z-10" />
            {models.flatMap((m) =>
              (
                [
                  ['P', t('metrics.precision')],
                  ['R', t('metrics.recall')],
                  ['F1', t('metrics.f1')],
                  ['TP', 'TP'],
                  ['FP', 'FP'],
                  ['FN', 'FN'],
                ] as const
              ).map(([short, full]) => (
                <th
                  key={`${m.name}-${short}`}
                  title={full}
                  className="px-2 py-1.5 text-[10px] font-medium text-[var(--text-muted)] text-center whitespace-nowrap border-l border-[var(--border)]"
                >
                  {short}
                </th>
              )),
            )}
          </tr>
        </thead>
        <tbody>
          {allTypes.map((vt) => (
            <tr key={vt} className="border-b border-[var(--border)] hover:bg-[var(--bg-card2)] transition-colors">
              <td className="px-3 py-2 text-xs font-mono whitespace-nowrap sticky left-0 bg-[var(--bg-card)] z-10">
                {vt}
              </td>
              {models.map((m) => {
                const b = byModel.get(m.name)?.find((x) => x.vuln_type === vt)
                return (
                  <TypeCells
                    key={m.name}
                    precision={num(b?.precision)}
                    recall={num(b?.recall)}
                    f1={num(b?.f1)}
                    tp={num(b?.tp)}
                    fp={num(b?.fp)}
                    fn={num(b?.fn)}
                    t={t}
                  />
                )
              })}
            </tr>
          ))}
          {/* 合计行：各模型 Findings.type.summary（缺则 buckets 汇总） */}
          <tr className="border-t-2 border-[var(--border-md)] font-medium">
            <td className="px-3 py-2 text-xs sticky left-0 bg-[var(--bg-card)] z-10">
              {t('compare.total')}
            </td>
            {models.map((m) => {
              const s = summaryOf(m.row)
              const buckets = byModel.get(m.name) ?? []
              const sum = (key: keyof Bucket): number | null => {
                const direct = num(s[key])
                if (direct != null) return direct
                const total = buckets.reduce(
                  (acc, b) => acc + (num(b[key]) ?? 0),
                  0,
                )
                return buckets.length ? total : null
              }
              return (
                <TypeCells
                  key={m.name}
                  precision={num(s.precision)}
                  recall={num(s.recall)}
                  f1={num(s.f1)}
                  tp={sum('tp')}
                  fp={sum('fp')}
                  fn={sum('fn')}
                  t={t}
                />
              )
            })}
          </tr>
        </tbody>
      </table>
    </div>
  )
}

/** 一行中某模型的 6 个指标格（P/R/F1 registry 格式化+着色，TP/FP/FN 计数）。 */
function TypeCells({
  precision,
  recall,
  f1,
  tp,
  fp,
  fn,
  t,
}: {
  precision: number | null
  recall: number | null
  f1: number | null
  tp: number | null
  fp: number | null
  fn: number | null
  t: (p: string) => string
}) {
  return (
    <>
      <td className="px-2 py-1.5 text-center whitespace-nowrap">
        <RatioCell metric="precision" value={precision} t={t} />
      </td>
      <td className="px-2 py-1.5 text-center whitespace-nowrap">
        <RatioCell metric="recall" value={recall} t={t} />
      </td>
      <td className="px-2 py-1.5 text-center whitespace-nowrap">
        <RatioCell metric="f1" value={f1} t={t} />
      </td>
      <td className="px-2 py-1.5 text-center font-mono tabular-nums whitespace-nowrap">{count(tp)}</td>
      <td className="px-2 py-1.5 text-center font-mono tabular-nums whitespace-nowrap">{count(fp)}</td>
      <td className="px-2 py-1.5 text-center font-mono tabular-nums whitespace-nowrap">{count(fn)}</td>
    </>
  )
}
