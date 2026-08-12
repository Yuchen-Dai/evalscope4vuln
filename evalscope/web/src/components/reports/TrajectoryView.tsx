/**
 * 漏洞挖掘轨迹展示（仿 vulnBenchmark/index.html）：按阶段（mine/verify/detect）展示
 * 图灵挖掘 session 的 step 时间线（thought/tool/finding/conclusion 着色）+ 统计磁贴 + legend。
 * 数据由后端 trace_view 适配（opencode part → step），前端纯渲染。
 */
import { useState, type ReactNode } from 'react'
import type { Trajectory, TraceStage, TraceStep } from '@/api/types'

const STEP_COLOR: Record<string, string> = {
  thought: '#a371f7',
  tool: '#4da3ff',
  finding: '#3fb950',
  conclusion: '#39c5cf',
  text: 'var(--text-muted)',
}
const STEP_LABEL: Record<string, string> = {
  thought: '思考', tool: '工具', finding: '入库', conclusion: '结论', text: '输出',
}
const STAGE_LABEL: Record<string, string> = { preprocess: '预处理', detect: '探测', mine: '挖掘', deepmine: '深度挖掘', verify: '验证' }

function fmtDuration(ms?: number | null): string {
  if (!ms) return '-'
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`
}

export default function TrajectoryView({ trajectory }: { trajectory: Trajectory }) {
  const { stages, stats } = trajectory

  return (
    <div className="flex flex-col gap-4">
      {/* 统计磁贴 */}
      <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 gap-2">
        <Stat label="步数" value={stats.total_steps} />
        <Stat label="工具调用" value={stats.tool_calls} />
        <Stat label="思考" value={stats.thoughts} />
        <Stat label="耗时" value={fmtDuration(stats.duration_ms)} />
        <Stat label="Token" value={(stats.tokens_input + stats.tokens_output).toLocaleString()} />
        <Stat label="结论" value={stats.conclusions} />
      </div>

      {/* 工具分布 */}
      {stats.tool_distribution && Object.keys(stats.tool_distribution).length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--text-muted)]">
          <span>工具分布:</span>
          {Object.entries(stats.tool_distribution).map(([k, v]) => (
            <span key={k} className="px-2 py-0.5 rounded bg-[var(--bg-card2)] border border-[var(--border)]">
              {k} ×{v}
            </span>
          ))}
        </div>
      )}

      <Legend />

      {/* 阶段轨迹（固定 5 阶段，可折叠，空阶段显示解释） */}
      {(['preprocess', 'detect', 'mine', 'deepmine', 'verify'] as const).map((stage) => (
        <StageSection key={stage} stage={stage} sessions={(stages as Record<string, TraceStage[]>)[stage] || []} />
      ))}
    </div>
  )
}

function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5 p-3 rounded-[var(--radius-sm)] bg-[var(--bg-card)] border border-[var(--border)]">
      <span className="text-xs text-[var(--text-muted)]">{label}</span>
      <span className="text-lg font-bold font-mono tabular-nums">{value}</span>
    </div>
  )
}

const EMPTY_REASON: Record<string, string> = {
  preprocess: '该项目未跑预处理阶段（无 preprocessing session）',
  detect: '未关联到该 finding 的探测 session——detect 按子类型批量探测，单个 detection_id 不在 session 文本中；需 finding 带 detection_source_task_id（已向图灵提诉求）才能精确关联',
  mine: '未关联到该 finding 的挖掘 session（finding.task_id 未命中任何 mining session）',
  deepmine: '该项目无横向处理（horizontal_processing）阶段',
  verify: '未关联到该 finding 的验证 session（无 validation_<finding_id>，或该 finding 未跑验证）',
}

function StageSection({ stage, sessions }: { stage: string; sessions: TraceStage[] }) {
  const [open, setOpen] = useState(true)
  const stepCount = sessions.reduce((n, s) => n + s.steps.length, 0)
  return (
    <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-card)] overflow-hidden">
      <button onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-2.5 cursor-pointer hover:bg-[var(--bg-card2)] transition-colors">
        <span className="text-sm font-semibold text-[var(--text)]">{STAGE_LABEL[stage] || stage}</span>
        <span className="text-xs text-[var(--text-muted)]">
          {sessions.length > 0 ? `${sessions.length} session · ${stepCount} 步` : '无数据'}
          <span className="ml-2">{open ? '▾' : '▸'}</span>
        </span>
      </button>
      {open && (
        <div className="px-3 py-2 border-t border-[var(--border)] flex flex-col gap-2">
          {sessions.length === 0 ? (
            <div className="text-xs text-[var(--text-muted)] py-2 leading-relaxed">{EMPTY_REASON[stage] || '无关联 session'}</div>
          ) : sessions.map((sess) => (
            <StageCard key={sess.task_id || sess.session_id || Math.random()} session={sess} />
          ))}
        </div>
      )}
    </div>
  )
}

function StageCard({ session }: { session: TraceStage }) {
  return (
    <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-card)] overflow-hidden">
      <div className="px-3 py-2 border-b border-[var(--border)] text-xs text-[var(--text-muted)] font-mono truncate">
        {session.task_type || session.session_id || session.task_id}
      </div>
      <div className="p-2">
        {session.steps.length === 0 ? (
          <div className="text-xs text-[var(--text-muted)] p-2">无 step</div>
        ) : (
          session.steps.map((step, i) => (
            <StepRow key={step.id} step={step} last={i === session.steps.length - 1} />
          ))
        )}
      </div>
    </div>
  )
}

function StepRow({ step, last }: { step: TraceStep; last: boolean }) {
  const [open, setOpen] = useState(false)
  const color = STEP_COLOR[step.type] || 'var(--text-muted)'
  const hasDetail = !!step.detail && step.detail !== step.summary
  return (
    <div className={`relative pl-6 ${last ? '' : 'pb-1'}`}>
      {!last && <div className="absolute left-[7px] top-3 bottom-0 w-px bg-[var(--border)]" />}
      <div
        className="absolute left-0 top-1.5 w-3.5 h-3.5 rounded-full"
        style={{ background: color, boxShadow: `0 0 0 2px var(--bg-card)` }}
      />
      <button
        onClick={() => hasDetail && setOpen(!open)}
        className={`w-full text-left ${hasDetail ? 'cursor-pointer hover:text-[var(--accent)]' : 'cursor-default'}`}
      >
        <div className="flex items-center gap-2 min-w-0">
          <span
            className="text-[10px] px-1.5 py-0.5 rounded shrink-0"
            style={{ background: `${color}22`, color }}
          >
            {STEP_LABEL[step.type] || step.type}
          </span>
          <span className="text-sm truncate">{step.summary || step.title}</span>
          {hasDetail && (
            <span className="text-[10px] text-[var(--text-muted)] shrink-0">{open ? '▾' : '▸'}</span>
          )}
        </div>
      </button>
      {open && hasDetail && (
        <pre className="mt-1 ml-1 p-2 rounded bg-[var(--bg-deep)] text-xs whitespace-pre-wrap break-words max-h-[300px] overflow-y-auto">
          {step.detail}
        </pre>
      )}
    </div>
  )
}

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--text-muted)] pt-2 border-t border-[var(--border)]">
      {Object.entries(STEP_LABEL).map(([k, label]) => (
        <span key={k} className="inline-flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: STEP_COLOR[k] }} />
          {label}
        </span>
      ))}
    </div>
  )
}
