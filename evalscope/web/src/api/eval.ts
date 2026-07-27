import { apiValidated } from './client'
import { benchmarksResponseSchema } from './schemas'
import type { BenchmarksResponse } from './types'
import { createTaskApi } from './task'

const evalTaskApi = createTaskApi('eval')

export const submitEvalTask = evalTaskApi.submit
export const getEvalProgress = evalTaskApi.progress
export const getEvalLog = evalTaskApi.log
export const getEvalReportUrl = evalTaskApi.reportUrl
export const stopEvalTask = evalTaskApi.stop
export const getEvalTasks = evalTaskApi.tasks

export async function listBenchmarks(
  type?: 'text' | 'multimodal',
  all?: boolean,
  signal?: AbortSignal,
): Promise<BenchmarksResponse> {
  const params: Record<string, string> = {}
  if (type) params.type = type
  if (all) params.all = 'true'
  return apiValidated('/api/v1/eval/benchmarks', benchmarksResponseSchema, { params, signal })
}

/** 图灵平台列表（供 platform 字段下拉补全）。 */
export async function listTuringPlatforms(signal?: AbortSignal): Promise<string[]> {
  const r = await fetch('/api/v1/eval/turing/platforms', { signal })
  if (!r.ok) return []
  return (await r.json()).map((p: { name: string }) => p.name)
}

/** 图灵指定平台的探测类型（供 detect-types 字段多选补全）。 */
export async function listTuringDetectTypes(platform: string, signal?: AbortSignal): Promise<{ value: string; label: string }[]> {
  const r = await fetch(`/api/v1/eval/turing/detect-types?platform=${encodeURIComponent(platform)}`, { signal })
  if (!r.ok) return []
  return (await r.json()).map((d: { value: string; label: string }) => ({ value: d.value, label: d.label }))
}
