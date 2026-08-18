// FnAnalysisTab（漏报分析 tab）渲染测试：FN 列表/状态徽标、中断 banner、无 trace 回退。
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { FnAdvice, PredictionsResponse } from '@/api/types'
import { LocaleProvider } from '@/contexts/LocaleContext'
import FnAnalysisTab from './FnAnalysisTab'

const { getPredictionsMock, getFnAdviceMock, getFnAdviceProgressMock } = vi.hoisted(() => ({
  getPredictionsMock: vi.fn(),
  getFnAdviceMock: vi.fn(),
  getFnAdviceProgressMock: vi.fn(),
}))

vi.mock('@/api/reports', () => ({
  getPredictions: getPredictionsMock,
  getFnAdvice: getFnAdviceMock,
  getFnAdviceProgress: getFnAdviceProgressMock,
}))

const mkPredictions = (): PredictionsResponse =>
  ({
    predictions: [{
      Index: '0',
      Score: {},
      NScore: 0,
      Findings: {
        scan: { findings_count: 2 },
        gt: [
          { gt_id: 'GT-001', vuln_type: 'sql-injection', missed: true, location: { file: 'a/UserController.java', line: 10 } },
          { gt_id: 'GT-002', vuln_type: 'xss', missed: true, location: { file: 'b/XssView.java' } },
          { gt_id: 'GT-003', vuln_type: 'rce', missed: false, matched_finding_ids: ['F-1'] },
        ],
        findings: [],
        missed_gt: ['GT-001', 'GT-002'],
        summary: {},
      },
    }],
  }) as unknown as PredictionsResponse

const adviceWithTrace: FnAdvice = {
  gt_id: 'GT-001',
  status: 'ok',
  advice: 'markdown',
  related_files: ['a/UserController.java'],
  advice_structured: {
    category: '挖掘深度不足',
    stages: ['mine'],
    reasoning: 'r',
    suggestions: ['s'],
    summary: 'm',
    trace: {
      steps: [
        { id: 's0', type: 'briefing', title: '探测开场', stage: 'detect' },
        { id: 's1', type: 'tool', title: '读取文件', stage: 'detect', tool: 'read' },
        { id: 's2', type: 'dead_end', title: '放弃该路径', stage: 'mine' },
      ],
      breakpoint: { stage: 'mine', step_id: 's2', reason: '判定误报后放弃', category: '挖掘深度不足' },
      story: ['[探测] 定位', '[挖掘] 放弃 ✗'],
    },
  },
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  getPredictionsMock.mockReset()
  getFnAdviceMock.mockReset()
  getFnAdviceProgressMock.mockReset()
})

const renderTab = (initialGtId?: string) =>
  render(
    <LocaleProvider>
      <FnAnalysisTab reportName="r" datasetName="vuln_jeecgboot" rootPath="/outputs" initialGtId={initialGtId} />
    </LocaleProvider>,
  )

describe('FnAnalysisTab', () => {
  it('lists missed GT with analysis status badges and hides non-missed GT', async () => {
    getPredictionsMock.mockResolvedValue(mkPredictions())
    getFnAdviceMock.mockResolvedValue({ 'GT-001': adviceWithTrace })
    getFnAdviceProgressMock.mockResolvedValue({ status: 'idle', percent: 0 })

    renderTab()

    await act(async () => { await Promise.resolve(); await Promise.resolve() })
    expect(screen.getByText('GT-001')).toBeInTheDocument()
    expect(screen.getByText('GT-002')).toBeInTheDocument()
    expect(screen.queryByText('GT-003')).not.toBeInTheDocument()   // 非 missed 不入列表
    expect(screen.getByText('Done')).toBeInTheDocument()           // GT-001 已完成
    expect(screen.getByText('Not analyzed')).toBeInTheDocument()   // GT-002 未分析
  })

  it('shows the breakpoint banner and interrupted timeline for a trace-bearing result', async () => {
    getPredictionsMock.mockResolvedValue(mkPredictions())
    getFnAdviceMock.mockResolvedValue({ 'GT-001': adviceWithTrace })
    getFnAdviceProgressMock.mockResolvedValue({ status: 'idle', percent: 0 })

    renderTab('GT-001')

    await act(async () => { await Promise.resolve(); await Promise.resolve() })
    // 中断 banner：阶段名 + 原因 + 中断点徽标
    expect(screen.getByText(/Turing was interrupted at the "Mine" stage/)).toBeInTheDocument()
    expect(screen.getByText('判定误报后放弃')).toBeInTheDocument()
    // 时间线：dead_end 步骤在 Mine 阶段内渲染
    expect(screen.getAllByText('放弃该路径').length).toBeGreaterThan(0)
  })

  it('falls back to the no-timeline hint for old-format results without trace', async () => {
    const legacy: FnAdvice = { gt_id: 'GT-002', status: 'ok', advice: 'plain', advice_structured: { summary: 's' } }
    getPredictionsMock.mockResolvedValue(mkPredictions())
    getFnAdviceMock.mockResolvedValue({ 'GT-002': legacy })
    getFnAdviceProgressMock.mockResolvedValue({ status: 'idle', percent: 0 })

    renderTab('GT-002')

    await act(async () => { await Promise.resolve(); await Promise.resolve() })
    expect(screen.getByText(/This result carries no timeline/)).toBeInTheDocument()
    expect(screen.queryByText(/Turing was interrupted/)).not.toBeInTheDocument()
  })
})
