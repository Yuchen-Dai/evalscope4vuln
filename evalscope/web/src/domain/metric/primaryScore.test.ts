import { describe, expect, it } from 'vitest'

import type { ReportData } from '@/api/types'
import { primaryMetricOf } from './primaryScore'

type MetricLike = ReportData['metrics'][number]

const metric = (name: string, score: number): MetricLike =>
  ({ name, score } as MetricLike)

const vulnReport = (score: number): ReportData =>
  ({
    name: 'r',
    dataset_name: 'vuln_flowise',
    model_name: 'm',
    score,
    analysis: '',
    metrics: [
      metric('Overall/F1', 0.5),
      metric('Overall/Precision', 0.6),
      metric('Overall/Recall', 0.45),
      metric('Overall/Coverage', 0.72),
      metric('LocOnly/Overall/F1', 0.55),
      metric('LocOnly/Overall/Coverage', 0.81),
    ],
  }) as unknown as ReportData

const plainReport = (): ReportData =>
  ({
    name: 'r',
    dataset_name: 'mmlu',
    model_name: 'm',
    score: 0.9,
    analysis: '',
    metrics: [metric('Average Accuracy', 0.9)],
  }) as unknown as ReportData

describe('primaryMetricOf', () => {
  it('prefers Overall/Coverage over metrics[0] (F1) on vuln reports', () => {
    const p = primaryMetricOf(vulnReport(0.5), 'type')
    expect(p.score).toBe(0.72)
    expect(p.metricName).toBe('Coverage')
  })

  it('prefers LocOnly/Overall/Coverage in the loc regime', () => {
    const p = primaryMetricOf(vulnReport(0.5), 'loc')
    expect(p.score).toBe(0.81)
    expect(p.metricName).toBe('Coverage')
  })

  it('falls back to metrics[0] (Report.score semantics) for non-vuln reports', () => {
    const p = primaryMetricOf(plainReport(), 'type')
    expect(p.score).toBe(0.9)
    expect(p.metricName).toBe('Average Accuracy')
  })

  it('falls back to LocOnly/<metrics[0]> then the type metric when Coverage is absent', () => {
    const legacy = {
      ...vulnReport(0.5),
      metrics: [metric('Overall/F1', 0.5), metric('LocOnly/Overall/F1', 0.42)],
    } as unknown as ReportData
    expect(primaryMetricOf(legacy, 'loc')).toEqual({ score: 0.42, metricName: 'F1' })
    expect(primaryMetricOf(legacy, 'type')).toEqual({ score: 0.5, metricName: 'F1' })
  })

  it('returns a registry-recognizable metric name so percent/ring rendering keeps working', () => {
    const p = primaryMetricOf(vulnReport(0.5), 'type')
    expect(p.metricName).not.toContain('/')
  })
})
