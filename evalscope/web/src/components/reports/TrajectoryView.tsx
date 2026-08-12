/**
 * 漏洞挖掘轨迹展示（仿 vulnBenchmark/index.html）：按阶段（mine/verify/detect）展示
 * 图灵挖掘 session 的 step 时间线（thought/tool/finding/conclusion 着色）+ 统计磁贴 + legend。
 * 数据由后端 trace_view 适配（opencode part → step），前端纯渲染。
 */
import { useState, type ReactNode } from 'react'
import { useLocale } from '@/contexts/LocaleContext'
import type { Trajectory, TraceStage, TraceStep } from '@/api/types'

const STEP_COLOR: Record<string, string> = {
  thought: '#a371f7',
  tool: '#4da3ff',
  finding: '#3fb950',
  conclusion: '#39c5cf',
  text: 'var(--text-muted)',
}

// step 类型 → i18n key（label 经 t() 取，避免模块顶层硬编码中文）
const STEP_LABEL_KEY: Record<string, string> = {
  thought: 'trace.stepThought',
  tool: 'trace.stepTool',
  finding: 'trace.stepFinding',
  conclusion: 'trace.stepConclusion',
  text: 'trace.stepText',
}
// 5 阶段 → i18n key
const STAGE_LABEL_KEY: Record<string, string> = {
  preprocess: 'trace.stagePreprocess',
  detect: 'trace.stageDetect',
  mine: 'trace.stageMine',
  deepmine: 'trace.stageDeepmine',
  verify: 'trace.stageVerify',
}
const STAGE_ORDER = ['preprocess', 'detect', 'mine', 'deepmine', 'verify'] as const

function fmtDuration(ms?: number | null): string {
  if (!ms) return '-'
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`
}

export default function TrajectoryView({ trajectory, variant = 'full' }: { trajectory: Trajectory; variant?: 'full' | 'stages' }) {
  const { t } = useLocale()
  const { stages, stats } = trajectory

  return (
    <div className="flex flex-col gap-4">
      {variant === 'full' && (
        <>
          {/* 统计磁贴 */}
          <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 gap-2">
            <Stat label={t('trace.statSteps')} value={stats.total_steps} />
            <Stat label={t('trace.statToolCalls')} value={stats.tool_calls} />
            <Stat label={t('trace.statThoughts')} value={stats.thoughts} />
            <Stat label={t('trace.statDuration')} value={fmtDuration(stats.duration_ms)} />
            <Stat label={t('trace.statTokens')} value={(stats.tokens_input + stats.tokens_output).toLocaleString()} />
            <Stat label={t('trace.statConclusions')} value={stats.conclusions} />
          </div>

          {/* 工具分布 */}
          {stats.tool_distribution && Object.keys(stats.tool_distribution).length > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--text-muted)]">
              <span>{t('trace.toolDistribution')}</span>
              {Object.entries(stats.tool_distribution).map(([k, v]) => (
                <span key={k} className="px-2 py-0.5 rounded bg-[var(--bg-card2)] border border-[var(--border)]">
                  {k} ×{v}
                </span>
              ))}
            </div>
          )}

          <Legend t={t} />
        </>
      )}

      {/* 阶段轨迹（固定 5 阶段，可折叠，空阶段显示解释） */}
      {STAGE_ORDER.map((stage) => (
        <StageSection key={stage} stage={stage} sessions={(stages as Record<string, TraceStage[]>)[stage] || []} t={t} />
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

// 空阶段理由 → i18n key
const EMPTY_REASON_KEY: Record<string, string> = {
  preprocess: 'trace.emptyPreprocess',
  detect: 'trace.emptyDetect',
  mine: 'trace.emptyMine',
  deepmine: 'trace.emptyDeepmine',
  verify: 'trace.emptyVerify',
}

type TFunc = (p: string, vars?: Record<string, string | number>) => string

function StageSection({ stage, sessions, t }: { stage: string; sessions: TraceStage[]; t: TFunc }) {
  const [open, setOpen] = useState(true)
  const stepCount = sessions.reduce((n, s) => n + s.steps.length, 0)
  const stageLabelKey = STAGE_LABEL_KEY[stage]
  return (
    <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-card)] overflow-hidden">
      <button onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-2.5 cursor-pointer hover:bg-[var(--bg-card2)] transition-colors">
        <span className="text-sm font-semibold text-[var(--text)]">{stageLabelKey ? t(stageLabelKey) : stage}</span>
        <span className="text-xs text-[var(--text-muted)]">
          {sessions.length > 0 ? t('trace.sessionSteps', { sessions: sessions.length, steps: stepCount }) : t('trace.noData')}
          <span className="ml-2">{open ? '▾' : '▸'}</span>
        </span>
      </button>
      {open && (
        <div className="px-3 py-2 border-t border-[var(--border)] flex flex-col gap-2">
          {sessions.length === 0 ? (
            <div className="text-xs text-[var(--text-muted)] py-2 leading-relaxed">{EMPTY_REASON_KEY[stage] ? t(EMPTY_REASON_KEY[stage]) : t('trace.noSession')}</div>
          ) : sessions.map((sess) => (
            <StageCard key={sess.task_id || sess.session_id || Math.random()} session={sess} t={t} />
          ))}
        </div>
      )}
    </div>
  )
}

function StageCard({ session, t }: { session: TraceStage; t: TFunc }) {
  return (
    <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-card)] overflow-hidden">
      <div className="px-3 py-2 border-b border-[var(--border)] text-xs text-[var(--text-muted)] font-mono truncate">
        {session.task_type || session.session_id || session.task_id}
      </div>
      <div className="p-2">
        {session.steps.length === 0 ? (
          <div className="text-xs text-[var(--text-muted)] p-2">{t('trace.noStep')}</div>
        ) : (
          session.steps.map((step, i) => (
            <StepRow key={step.id} step={step} last={i === session.steps.length - 1} t={t} />
          ))
        )}
      </div>
    </div>
  )
}

function StepRow({ step, last, t }: { step: TraceStep; last: boolean; t: TFunc }) {
  const [open, setOpen] = useState(false)
  const color = STEP_COLOR[step.type] || 'var(--text-muted)'
  const hasDetail = !!step.detail && step.detail !== step.summary
  const labelKey = STEP_LABEL_KEY[step.type]
  const hasLoc = !!step.file
  // 长路径只保留 basename（+ 父目录），便于一眼定位文件；hover title 看全路径。
  const shortPath = step.file ? step.file.replace(/^.*\//, '') : ''
  const locLabel = hasLoc ? (step.line ? `${shortPath}:${step.line}` : shortPath) : ''
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
            {labelKey ? t(labelKey) : step.type}
          </span>
          <span className="text-sm truncate">{step.summary || step.title}</span>
          {hasLoc && (
            <span
              className="text-[10px] font-mono text-[var(--text-muted)] shrink-0 max-w-[40%] truncate"
              title={hasLoc ? (step.line ? `${step.file}:${step.line}` : step.file) : undefined}
            >
              {locLabel}
            </span>
          )}
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

function Legend({ t }: { t: TFunc }) {
  return (
    <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--text-muted)] pt-2 border-t border-[var(--border)]">
      {Object.entries(STEP_LABEL_KEY).map(([k, labelKey]) => (
        <span key={k} className="inline-flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: STEP_COLOR[k] }} />
          {t(labelKey)}
        </span>
      ))}
    </div>
  )
}
