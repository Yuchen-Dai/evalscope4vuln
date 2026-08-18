// groupFnTraceSteps（FN 中断轨迹分组）纯逻辑测试。
import { describe, expect, it } from 'vitest'

import type { FnTrace } from '@/api/types'
import { groupFnTraceSteps } from './fnTrace'

const step = (id: string, stage: string | undefined, type: FnTrace['steps'][number]['type']) =>
  ({ id, stage, type, title: `t-${id}` }) as FnTrace['steps'][number]

describe('groupFnTraceSteps', () => {
  it('groups flat steps into the 5 stages and derives stats', () => {
    const trace: FnTrace = {
      steps: [
        step('s0', 'preprocess', 'briefing'),
        step('s1', 'detect', 'thought'),
        step('s2', 'detect', 'tool'),
        step('s3', 'mine', 'dead_end'),
      ],
      story: ['a', 'b'],
    }
    const grouped = groupFnTraceSteps(trace)
    expect(grouped).not.toBeNull()
    expect(grouped!.stages.preprocess).toHaveLength(1)
    expect(grouped!.stages.detect).toHaveLength(1)   // 伪 session
    expect(grouped!.stages.detect[0].steps).toHaveLength(2)
    expect(grouped!.stages.mine[0].steps[0].id).toBe('s3')
    expect(grouped!.stages.verify).toHaveLength(0)
    expect(grouped!.stats.total_steps).toBe(4)
    expect(grouped!.stats.tool_calls).toBe(1)
    expect(grouped!.stats.thoughts).toBe(1)
    expect(grouped!.stats.tokens_input).toBe(0)
    expect(grouped!.story).toEqual(['a', 'b'])
  })

  it('carries forward the last valid stage when stage is missing or invalid', () => {
    const trace: FnTrace = {
      steps: [
        step('s0', 'detect', 'briefing'),
        step('s1', undefined, 'tool'),      // 缺失 → 沿用 detect
        step('s2', '乱写', 'thought'),      // 非法 → 沿用 detect
        step('s3', 'verify', 'conclusion'),
      ],
    }
    const grouped = groupFnTraceSteps(trace)!
    expect(grouped.stages.detect[0].steps.map((s) => s.id)).toEqual(['s0', 's1', 's2'])
    expect(grouped.stages.verify[0].steps.map((s) => s.id)).toEqual(['s3'])
  })

  it('defaults the first stage to detect and returns null for empty traces', () => {
    const grouped = groupFnTraceSteps({ steps: [step('s0', undefined, 'tool')] })
    expect(grouped!.stages.detect[0].steps).toHaveLength(1)   // 首个默认 detect
    expect(groupFnTraceSteps(undefined)).toBeNull()
    expect(groupFnTraceSteps({ steps: [] })).toBeNull()
  })
})
