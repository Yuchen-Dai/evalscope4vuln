/**
 * 挖掘轨迹对比视图（仿 index.html 并排）：顶部统计对照矩阵 + N 列并排
 * （每列一模型对该 gt 的轨迹；漏报/老报告列显示空态）。
 * 列内复用 TrajectoryView(variant='stages')，只渲染 5 阶段时间线。
 */
import type { TrajectoryCompareRun } from '@/api/types'
import TrajectoryView from './TrajectoryView'

interface Props {
  runs: TrajectoryCompareRun[]
  displayLabels: Record<string, string>
}

const STATUS_LABEL: Record<string, string> = {
  tp: '✓ 命中',
  fn: '✗ 漏报',
  unavailable: '— 不可用',
}
const STATUS_COLOR: Record<string, string> = {
  tp: 'var(--success, #3fb950)',
  fn: 'var(--danger, #f85149)',
  unavailable: 'var(--text-muted)',
}

function fmtDuration(ms?: number | null): string {
  if (!ms) return '-'
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`
}

// 统计对照矩阵指标行（s 为某 run 的 trajectory.stats，无 trajectory 时上层显示 —）
const METRICS: { key: string; label: string; fmt: (s: any) => string }[] = [
  { key: 'total_steps', label: '步数', fmt: (s) => String(s.total_steps ?? '-') },
  { key: 'tool_calls', label: '工具调用', fmt: (s) => String(s.tool_calls ?? '-') },
  { key: 'thoughts', label: '思考', fmt: (s) => String(s.thoughts ?? '-') },
  { key: 'duration_ms', label: '耗时', fmt: (s) => fmtDuration(s.duration_ms) },
  { key: 'tokens', label: 'Token', fmt: (s) => ((s.tokens_input || 0) + (s.tokens_output || 0)).toLocaleString() },
  { key: 'findings', label: '入库', fmt: (s) => String(s.findings ?? '-') },
]

export default function TrajectoryCompareView({ runs, displayLabels }: Props) {
  return (
    <div className="flex flex-col gap-4">
      {/* 统计对照矩阵（指标 × 模型） */}
      <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-card)] overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left px-3 py-2 text-xs text-[var(--text-muted)] font-medium whitespace-nowrap">指标</th>
              {runs.map((run, i) => (
                <th key={run.report_name} className="text-left px-3 py-2 text-xs font-semibold whitespace-nowrap"
                  style={{ color: `var(--compare-${i % 3}-dot)` }}>
                  {displayLabels[run.report_name] || run.display_label || run.report_name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-[var(--border)]">
              <td className="px-3 py-2 text-xs text-[var(--text-muted)]">命中</td>
              {runs.map((run) => (
                <td key={run.report_name} className="px-3 py-2 text-sm font-semibold"
                  style={{ color: STATUS_COLOR[run.status] }}>
                  {STATUS_LABEL[run.status] || run.status}
                </td>
              ))}
            </tr>
            {METRICS.map((m) => (
              <tr key={m.key} className="border-b border-[var(--border)] last:border-b-0">
                <td className="px-3 py-2 text-xs text-[var(--text-muted)]">{m.label}</td>
                {runs.map((run) => (
                  <td key={run.report_name} className="px-3 py-2 font-mono tabular-nums">
                    {run.trajectory ? m.fmt(run.trajectory.stats) : '—'}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* N 列并排（仿 index.html .compare，sticky 列头） */}
      <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${runs.length}, minmax(0, 1fr))` }}>
        {runs.map((run, i) => {
          const label = displayLabels[run.report_name] || run.display_label || run.report_name
          return (
            <div key={run.report_name} className="rounded-[var(--radius-sm)] border bg-[var(--bg-card)] overflow-hidden"
              style={{ borderColor: `var(--compare-${i % 3}-border)` }}>
              <div className="sticky top-0 z-10 px-3 py-2 border-b text-sm font-semibold flex items-center justify-between gap-2"
                style={{ background: `var(--compare-${i % 3}-bg-header)`, borderBottomColor: `var(--compare-${i % 3}-border)` }}>
                <span className="truncate">{label}</span>
                <span className="text-xs px-1.5 py-0.5 rounded shrink-0"
                  style={{ color: STATUS_COLOR[run.status], background: 'var(--bg-card)' }}>
                  {STATUS_LABEL[run.status]}
                </span>
              </div>
              <div className="p-2 max-h-[70vh] overflow-y-auto">
                {run.trajectory ? (
                  <TrajectoryView trajectory={run.trajectory} variant="stages" />
                ) : (
                  <div className="text-xs text-[var(--text-muted)] p-4 leading-relaxed">
                    {run.status === 'fn' ? '该模型未挖到此漏洞（漏报）' : run.reason || '无轨迹数据'}
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
