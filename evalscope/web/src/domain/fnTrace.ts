/**
 * FN 漏报分析纯逻辑：阶段标签映射 + agent 重构的扁平中断轨迹 → TrajectoryView
 * 的 5 阶段结构分组（独立于组件文件，供 FnAnalysisTab / TrajectoryView 与测试复用）。
 */
import type { FnTrace, Trajectory } from '@/api/types'

export const TRACE_STAGE_ORDER = ['preprocess', 'detect', 'mine', 'deepmine', 'verify'] as const
export type TraceStageKey = (typeof TRACE_STAGE_ORDER)[number]

/** 5 阶段 → i18n key（TrajectoryView 阶段标题、FnAnalysisTab 中断 banner 复用）。 */
export const TRACE_STAGE_LABEL_KEY: Record<string, string> = {
  preprocess: 'trace.stagePreprocess',
  detect: 'trace.stageDetect',
  mine: 'trace.stageMine',
  deepmine: 'trace.stageDeepmine',
  verify: 'trace.stageVerify',
}

/**
 * agent 重构的扁平 steps → TrajectoryView 的 5 阶段结构（每阶段一个伪 session）。
 * stage 缺失/非法沿用上一有效 stage（首个默认 detect），保证叙事不丢。
 * stats 派生（tokens 无来源全 0）；trace 为空 → null（调用方隐藏时间线）。
 */
export function groupFnTraceSteps(trace?: FnTrace): Trajectory | null {
  if (!trace || trace.steps.length === 0) return null
  const buckets: Record<TraceStageKey, FnTrace['steps']> = {
    preprocess: [], detect: [], mine: [], deepmine: [], verify: [],
  }
  let lastStage: TraceStageKey = 'detect'
  for (const step of trace.steps) {
    const raw: string | undefined = step.stage
    const stage: TraceStageKey =
      (TRACE_STAGE_ORDER as readonly string[]).includes(raw ?? '') ? (raw as TraceStageKey) : lastStage
    lastStage = stage
    buckets[stage].push(step)
  }
  const stages: Trajectory['stages'] = {
    preprocess: [], detect: [], mine: [], deepmine: [], verify: [],
  }
  for (const stage of TRACE_STAGE_ORDER) {
    if (buckets[stage].length > 0) {
      stages[stage] = [{ task_id: 'fn-analysis', task_type: '漏报轨迹归因（agent 重构）', steps: buckets[stage] }]
    }
  }
  const toolDistribution: Record<string, number> = {}
  for (const s of trace.steps) {
    if (s.type === 'tool' && s.tool) toolDistribution[s.tool] = (toolDistribution[s.tool] ?? 0) + 1
  }
  const count = (type: string) => trace.steps.filter((s) => s.type === type).length
  return {
    stages,
    stats: {
      total_steps: trace.steps.length,
      tool_calls: count('tool'),
      thoughts: count('thought'),
      findings: count('finding'),
      conclusions: count('conclusion'),
      tokens_input: 0,
      tokens_output: 0,
      tool_distribution: toolDistribution,
    },
    story: trace.story,
  }
}
