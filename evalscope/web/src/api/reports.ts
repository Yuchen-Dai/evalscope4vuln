import { apiPostValidated, apiValidated } from './client'
import {
  analysisResponseSchema,
  dataFrameResponseSchema,
  fnAdviceInvokeResponseSchema,
  fnAdviceProgressSchema,
  fnAdviceResponseSchema,
  fnAdviceSchema,
  fnAdviceStopResponseSchema,
  listReportsResponseSchema,
  loadReportResponseSchema,
  predictionsResponseSchema,
  scanResponseSchema,
  trajectoryCompareSchema,
  trajectorySchema,
} from './schemas'
import type {
  AnalysisResponse,
  DataFrameResponse,
  FnAdvice,
  FnAdviceInvokeResponse,
  FnAdviceProgress,
  FnAdviceResponse,
  FnAdviceStopResponse,
  ListReportsResponse,
  LoadReportResponse,
  PredictionsResponse,
  ScanResponse,
  Trajectory,
  TrajectoryCompare,
} from './types'

const BASE = '/api/v1/reports'

export async function listReports(params: {
  rootPath: string
  search?: string
  models?: string[]
  datasets?: string[]
  scoreMin?: number
  scoreMax?: number
  sortBy?: 'score' | 'model' | 'dataset' | 'time'
  sortOrder?: 'asc' | 'desc'
  page?: number
  pageSize?: number
  /** Optional signal to cancel a superseded list/search request. */
  signal?: AbortSignal
}): Promise<ListReportsResponse> {
  return apiValidated(`${BASE}/list`, listReportsResponseSchema, {
    params: {
      root_path: params.rootPath,
      search: params.search,
      models: params.models?.join(';'),
      datasets: params.datasets?.join(';'),
      score_min: params.scoreMin,
      score_max: params.scoreMax,
      sort_by: params.sortBy,
      sort_order: params.sortOrder,
      page: params.page,
      page_size: params.pageSize,
    },
    signal: params.signal,
  })
}

export async function scanReports(rootPath: string, signal?: AbortSignal): Promise<string[]> {
  const res: ScanResponse = await apiValidated(`${BASE}/scan`, scanResponseSchema, {
    params: { root_path: rootPath },
    signal,
  })
  return res.reports
}

export async function deleteReport(reportName: string): Promise<void> {
  const r = await fetch(`${BASE}/delete?report_name=${encodeURIComponent(reportName)}`, { method: 'DELETE' })
  if (!r.ok) throw new Error(`删除失败: ${r.status}`)
}

export async function loadReport(
  rootPath: string,
  reportName: string,
  signal?: AbortSignal,
): Promise<LoadReportResponse> {
  return apiValidated(`${BASE}/load`, loadReportResponseSchema, {
    params: { root_path: rootPath, report_name: reportName },
    signal,
  })
}

export async function getDataFrame(
  rootPath: string,
  reportName: string,
  type: 'acc' | 'compare' | 'dataset' = 'acc',
  datasetName?: string,
  signal?: AbortSignal,
): Promise<DataFrameResponse> {
  return apiValidated(`${BASE}/dataframe`, dataFrameResponseSchema, {
    params: {
      root_path: rootPath,
      report_name: reportName,
      type,
      dataset_name: datasetName,
    },
    signal,
  })
}

export async function getPredictions(
  rootPath: string,
  reportName: string,
  datasetName: string,
  subsetName: string,
  signal?: AbortSignal,
): Promise<PredictionsResponse> {
  return apiValidated(`${BASE}/predictions`, predictionsResponseSchema, {
    params: {
      root_path: rootPath,
      report_name: reportName,
      dataset_name: datasetName,
      subset_name: subsetName,
    },
    signal,
  })
}

export async function getAnalysis(
  rootPath: string,
  reportName: string,
  datasetName: string,
  signal?: AbortSignal,
): Promise<string> {
  const res: AnalysisResponse = await apiValidated(`${BASE}/analysis`, analysisResponseSchema, {
    params: {
      root_path: rootPath,
      report_name: reportName,
      dataset_name: datasetName,
    },
    signal,
  })
  return res.analysis
}

/** 对单个漏报(FN)漏洞跑 LLM 路径分析（全量由前端循环调用）。 */
export async function postFnAdvice(
  rootPath: string,
  reportName: string,
  datasetName: string,
  gtId?: string,
  signal?: AbortSignal,
): Promise<FnAdvice> {
  return apiPostValidated(`${BASE}/fn-advice`, {
    root_path: rootPath,
    report_name: reportName,
    dataset_name: datasetName,
    ...(gtId ? { gt_id: gtId } : {}),
  }, fnAdviceSchema, { signal })
}

/** 读取已缓存的 FN 漏报分析结果（前端初次加载用）。 */
export async function getFnAdvice(
  rootPath: string,
  reportName: string,
  datasetName: string,
  signal?: AbortSignal,
): Promise<Record<string, FnAdvice>> {
  const res: FnAdviceResponse = await apiValidated(`${BASE}/fn-advice`, fnAdviceResponseSchema, {
    params: { root_path: rootPath, report_name: reportName, dataset_name: datasetName },
    signal,
  })
  return res.advice
}

/** 异步起 FN 全量分析任务（线程），立即返回 task_id。task_id 经 header 传（与 eval 一致）。 */
export async function startFnAdviceTask(
  rootPath: string,
  reportName: string,
  datasetName: string,
  taskId: string,
  signal?: AbortSignal,
): Promise<FnAdviceInvokeResponse> {
  return apiPostValidated(`${BASE}/fn-advice/invoke`, {
    root_path: rootPath, report_name: reportName, dataset_name: datasetName,
  }, fnAdviceInvokeResponseSchema, {
    headers: { 'EvalScope-Task-Id': taskId }, signal,
  })
}

/** 查 FN 分析任务进度（按 report+dataset 维度，前端切走切回判 running）。 */
export async function getFnAdviceProgress(
  rootPath: string,
  reportName: string,
  datasetName: string,
  signal?: AbortSignal,
): Promise<FnAdviceProgress> {
  return apiValidated(`${BASE}/fn-advice/progress`, fnAdviceProgressSchema, {
    params: { root_path: rootPath, report_name: reportName, dataset_name: datasetName },
    signal,
  })
}

/** 停止 FN 分析任务（worker 下个 gt_id 边界退出，已完成结果已落盘）。 */
export async function stopFnAdviceTask(
  taskId: string,
  signal?: AbortSignal,
): Promise<FnAdviceStopResponse> {
  return apiPostValidated(`${BASE}/fn-advice/stop`, {}, fnAdviceStopResponseSchema, {
    params: { task_id: taskId }, signal,
  })
}

/** 按 finding 关联各阶段 session 轨迹（mine/verify/detect）+ 统计。 */
export async function getTraceForFinding(
  rootPath: string,
  reportName: string,
  datasetName: string,
  taskId: string,
  findingId?: string,
  vulnType?: string,
  detectionId?: string,
  detectionSourceTaskId?: string,
  signal?: AbortSignal,
): Promise<Trajectory> {
  return apiValidated(`${BASE}/trace/for-finding`, trajectorySchema, {
    params: {
      root_path: rootPath, report_name: reportName, dataset_name: datasetName, task_id: taskId,
      ...(findingId ? { finding_id: findingId } : {}),
      ...(vulnType ? { vuln_type: vulnType } : {}),
      ...(detectionId ? { detection_id: detectionId } : {}),
      ...(detectionSourceTaskId ? { detection_source_task_id: detectionSourceTaskId } : {}),
    },
    signal,
  })
}

/** 跨模型同一 gt_id 的挖掘轨迹对比（并排对照用）。 */
export async function compareTrajectory(
  rootPath: string, reportNames: string[], datasetName: string, gtId: string, signal?: AbortSignal,
): Promise<TrajectoryCompare> {
  return apiPostValidated(`${BASE}/compare/trace`, {
    root_path: rootPath, report_names: reportNames, dataset_name: datasetName, gt_id: gtId,
  }, trajectoryCompareSchema, { signal })
}

export function getHtmlReportUrl(rootPath: string, reportName: string): string {
  return `${BASE}/html?root_path=${encodeURIComponent(rootPath)}&report_name=${encodeURIComponent(reportName)}`
}

export function getChartUrl(
  rootPath: string,
  chartType: 'scores' | 'sunburst' | 'dataset_scores' | 'radar' | 'histogram' | 'grouped_bar',
  opts: { reportName?: string; reportNames?: string[]; datasetName?: string; subsetName?: string } = {},
): string {
  const params = new URLSearchParams({ root_path: rootPath, chart_type: chartType })
  if (opts.reportName) params.set('report_name', opts.reportName)
  if (opts.reportNames?.length) params.set('report_names', opts.reportNames.join(';'))
  if (opts.datasetName) params.set('dataset_name', opts.datasetName)
  if (opts.subsetName) params.set('subset_name', opts.subsetName)
  return `${BASE}/chart?${params.toString()}`
}
