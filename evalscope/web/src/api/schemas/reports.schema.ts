/**
 * Runtime (zod) schemas for the "reports" API domain.
 *
 * These schemas are the runtime and TypeScript source of truth for report,
 * prediction, comparison, and analysis endpoint responses. Public type import
 * paths remain stable through the domain barrels while the types use `z.infer`.
 *
 * Covers: LoadReportResponse, ListReportsResponse, PredictionsResponse.
 */
import { z } from 'zod'

// ------------------------------------------------------------------ //
// Report score tree                                                   //
// ------------------------------------------------------------------ //

/** Runtime contract for a subset score. */
export const subsetDataSchema = z.object({
  name: z.string(),
  score: z.number(),
  num: z.number(),
})

/** Runtime contract for a category score. */
export const categoryDataSchema = z.object({
  name: z.array(z.string()),
  num: z.number(),
  score: z.number(),
  subsets: z.array(subsetDataSchema),
})

/** Runtime contract for a metric score tree. */
export const metricDataSchema = z.object({
  name: z.string(),
  num: z.number(),
  score: z.number(),
  categories: z.array(categoryDataSchema),
})

// ------------------------------------------------------------------ //
// Performance metrics embedded on a report                            //
// ------------------------------------------------------------------ //

/** Runtime contract for report-level percentile statistics. */
export const percentileStatsSchema = z.object({
  mean: z.number(),
  // pandas uses sample standard deviation (ddof=1), which is undefined for a
  // single observation. The backend serializes that NaN as JSON null.
  std: z.number().nullable(),
  min: z.number(),
  '25%': z.number(),
  '50%': z.number(),
  '75%': z.number(),
  '90%': z.number(),
  '99%': z.number(),
  max: z.number(),
})

/** Runtime contract for embedded performance summary data. */
export const perfMetricsSummarySchema = z.object({
  n_samples: z.number(),
  latency: percentileStatsSchema,
  throughput: z.object({
    avg_output_tps: z.number(),
    avg_req_ps: z.number(),
  }),
  usage: z.object({
    input_tokens: percentileStatsSchema,
    output_tokens: percentileStatsSchema,
    total_tokens: percentileStatsSchema,
    total_input_tokens: z.number().optional(),
    total_output_tokens: z.number().optional(),
    total_tokens_count: z.number().optional(),
  }),
  ttft: percentileStatsSchema.optional(),
  tpot: percentileStatsSchema.optional(),
})

/** Runtime contract for embedded performance metrics. */
export const perfMetricsSchema = z.object({
  summary: perfMetricsSummarySchema,
})

/** Runtime contract for one dataset report. */
export const reportDataSchema = z.object({
  name: z.string(),
  dataset_name: z.string(),
  model_name: z.string(),
  score: z.number(),
  analysis: z.string(),
  metrics: z.array(metricDataSchema),
  // Reports created without collect_perf persist this field as null rather
  // than omitting it. Both shapes are part of the backend contract.
  perf_metrics: perfMetricsSchema.nullable().optional(),
})

/** Runtime contract for a report detail response. */
export const loadReportResponseSchema = z.object({
  report_list: z.array(reportDataSchema),
  datasets: z.array(z.string()),
  task_config: z.record(z.string(), z.unknown()),
})

// ------------------------------------------------------------------ //
// Report list / summary                                               //
// ------------------------------------------------------------------ //

/** Runtime contract for a vuln-mining summary (TP/FP/FN aggregated across datasets). */
export const vulnSummarySchema = z.object({
  tp: z.number(),
  fp: z.number(),
  fn: z.number(),
  recall: z.number(),
})

/** Runtime contract for one report-list item. */
export const reportSummarySchema = z.object({
  name: z.string(),
  model_name: z.string(),
  dataset_name: z.string(),
  score: z.number(),
  metric_name: z.string().optional(),
  dataset_scores: z.record(z.string(), z.number()).optional(),
  num_samples: z.number(),
  timestamp: z.string(),
  // Vuln-mining counts. Absent on non-vuln reports / legacy data; the UI
  // degrades gracefully (em-dash / hidden column) when this is missing/null.
  vuln_summary: vulnSummarySchema.nullable().optional(),
})

/** Runtime contract for a paginated report list. */
export const listReportsResponseSchema = z.object({
  reports: z.array(reportSummarySchema),
  total: z.number(),
  page: z.number(),
  page_size: z.number(),
  filters: z.object({
    available_models: z.array(z.string()),
    available_datasets: z.array(z.string()),
  }),
})

// ------------------------------------------------------------------ //
// Prediction rows (chat messages + agent trace)                       //
// ------------------------------------------------------------------ //

/** Runtime contract for message/sample performance metadata. */
export const samplePerfMetricsSchema = z.object({
  latency: z.number(),
  ttft: z.number().nullable().optional(),
  tpot: z.number().nullable().optional(),
  input_tokens: z.number(),
  output_tokens: z.number(),
})

/** Runtime contract for a structured message content block. */
export const contentBlockSchema = z.object({
  type: z.enum(['text', 'reasoning', 'image', 'audio', 'video', 'data']),
  text: z.string().optional(),
  reasoning: z.string().optional(),
  reasoning_tokens: z.number().optional(),
  image: z.string().optional(),
  audio: z.string().optional(),
  video: z.string().optional(),
  format: z.string().optional(),
  detail: z.string().optional(),
  data: z.record(z.string(), z.unknown()).optional(),
})

/** Runtime contract for a tool call. */
export const toolCallSchema = z.object({
  id: z.string(),
  function: z.string(),
  arguments: z.record(z.string(), z.unknown()),
})

/** Runtime contract for a tool-result error. */
export const toolMessageErrorSchema = z.object({
  type: z.string().nullable().optional(),
  message: z.string(),
})

/** Runtime contract for a chronological chat message. */
export const chatMessageSchema = z.object({
  id: z.string().optional(),
  role: z.enum(['system', 'user', 'assistant', 'tool']),
  content: z.union([z.string(), z.array(contentBlockSchema)]),
  perf_metrics: samplePerfMetricsSchema.nullable().optional(),
  tool_calls: z.array(toolCallSchema).nullable().optional(),
  model: z.string().nullable().optional(),
  tool_call_id: z.string().nullable().optional(),
  function: z.string().nullable().optional(),
  error: toolMessageErrorSchema.nullable().optional(),
})

/** Accepted agent trace event types. */
export const agentTraceEventTypeSchema = z.enum([
  'model_generate',
  'tool_call',
  'tool_result',
  'env_exec',
  'error',
  'nudge',
  'submit',
  'run_start',
  'run_end',
])

/** Runtime contract for one chronological agent trace event. */
export const agentTraceEventSchema = z.object({
  step: z.number(),
  timestamp: z.number(),
  type: agentTraceEventTypeSchema,
  message_id: z.string().nullable().optional(),
  latency_ms: z.number().nullable().optional(),
  token_usage: z
    .object({
      input: z.number().optional(),
      output: z.number().optional(),
      total: z.number().optional(),
    })
    .nullable()
    .optional(),
  payload: z.record(z.string(), z.unknown()),
})

/** Runtime contract for an agent trace. */
export const agentTraceSchema = z.object({
  strategy: z.string().nullable().optional(),
  environment: z.string().nullable().optional(),
  max_steps: z.number(),
  events: z.array(agentTraceEventSchema),
})

/** vuln_scan: 漏洞浏览视图（GT↔finding 匹配详情）。仅 vuln benchmark 的 PredictionRow 有 Findings。 */
const vulnLocationSchema = z.object({
  file: z.string().nullable().optional(),
  line: z.number().nullable().optional(),
  line_range: z.array(z.number()).nullable().optional(),
  function: z.string().nullable().optional(),
}).passthrough()

const vulnGtSchema = z.object({
  gt_id: z.string(),
  vuln_type: z.string().nullable().optional(),
  cwe: z.string().nullable().optional(),
  severity: z.string().nullable().optional(),
  location: vulnLocationSchema.nullable().optional(),
  description: z.string().nullable().optional(),
  matched_finding_ids: z.array(z.string()).optional(),
  missed: z.boolean().optional(),
  matched_finding_ids_loc: z.array(z.string()).optional(),
  missed_loc: z.boolean().optional(),
}).passthrough()

const vulnFindingSchema = z.object({
  finding_id: z.string().nullable().optional(),
  display_id: z.string().nullable().optional(),
  vuln_type: z.string().nullable().optional(),
  severity: z.string().nullable().optional(),
  confidence: z.number().nullable().optional(),
  validation_result: z.string().nullable().optional(),
  title: z.string().nullable().optional(),
  description: z.string().nullable().optional(),
  classification: z.enum(['TP', 'FP']).nullable().optional(),
  gt_id: z.string().nullable().optional(),
  classification_loc: z.enum(['TP', 'FP']).nullable().optional(),
  gt_id_loc: z.string().nullable().optional(),
  raw: z.record(z.string(), z.unknown()).nullable().optional(),
}).passthrough()

const vulnRegimeSchema = z.object({
  summary: z.record(z.string(), z.unknown()),
  buckets: z.array(z.record(z.string(), z.unknown())).optional(),
}).passthrough()

const vulnFindingsSchema = z.object({
  scan: z.object({ findings_count: z.number() }).passthrough(),
  gt: z.array(vulnGtSchema),
  findings: z.array(vulnFindingSchema),
  missed_gt: z.array(z.string()),
  summary: z.record(z.string(), z.unknown()),
  type: vulnRegimeSchema.optional(),
  loc: vulnRegimeSchema.optional(),
}).passthrough()

/** Mirrors `PredictionRow`. */
export const predictionRowSchema = z.object({
  Index: z.string(),
  Input: z.string(),
  Metadata: z.unknown(),
  Generated: z.string(),
  Gold: z.string(),
  Pred: z.string(),
  Score: z.record(z.string(), z.unknown()),
  NScore: z.number(),
  PerfMetrics: samplePerfMetricsSchema.nullable().optional(),
  Messages: z.array(chatMessageSchema).nullable().optional(),
  AgentTrace: agentTraceSchema.nullable().optional(),
  Findings: vulnFindingsSchema.nullable().optional(),
})

/** Mirrors `PredictionsResponse`. */
export const predictionsResponseSchema = z.object({
  predictions: z.array(predictionRowSchema),
})

export const scanResponseSchema = z.object({
  reports: z.array(z.string()),
})

export const analysisResponseSchema = z.object({
  analysis: z.string(),
})

/** FN 漏报 LLM-as-judge 路径分析结果（单个漏报漏洞）。 */
export const fnAdviceSchema = z.object({
  gt_id: z.string(),
  advice: z.string().nullable().optional(),
  status: z.enum(['ok', 'error']),
  error: z.string().nullable().optional(),
  related_files: z.array(z.string()).optional(),
  related_sessions: z.number().optional(),
  ts: z.number().optional(),
}).passthrough()

/** GET /fn-advice 返回 { advice: { gt_id: fnAdvice } }。 */
export const fnAdviceResponseSchema = z.object({
  advice: z.record(z.string(), fnAdviceSchema),
})

/** FN 分析任务进度（GET /fn-advice/progress，按 report+dataset 维度）。 */
export const fnAdviceProgressSchema = z.object({
  status: z.string(),                  // idle/running/completed/error/stopped
  percent: z.number(),
  pipeline: z.string().optional(),
  dataset: z.string().nullable().optional(),
  task_id: z.string().nullable().optional(),
  total_count: z.number().optional(),
  processed_count: z.number().optional(),
  current_gt_id: z.string().nullable().optional(),
  errors: z.array(z.string()).optional(),
  error: z.string().nullable().optional(),
  updated_at: z.string().nullable().optional(),
}).passthrough()

/** POST /fn-advice/invoke 响应（status=running + task_id，或 status=error + error）。 */
export const fnAdviceInvokeResponseSchema = z.object({
  status: z.string(),
  task_id: z.string().nullable().optional(),
  error: z.string().nullable().optional(),
}).passthrough()

/** POST /fn-advice/stop 响应。 */
export const fnAdviceStopResponseSchema = z.object({
  status: z.string(),
  task_id: z.string(),
}).passthrough()

/** 挖掘轨迹：一个 step 节点（opencode part 适配）。 */
export const traceStepSchema = z.object({
  id: z.string(),
  type: z.enum(['thought', 'tool', 'finding', 'conclusion', 'text']),
  title: z.string(),
  summary: z.string(),
  detail: z.string().optional(),
  time: z.number().nullable().optional(),
  tool: z.string().optional(),
  // best-effort 源码位置：从 tool input 提取的 file + 行号；read/grep/edit 类工具才有。
  file: z.string().optional(),
  line: z.number().nullable().optional(),
}).passthrough()

/** 轨迹阶段：一个 session（mine/verify/detect）。 */
export const traceStageSchema = z.object({
  task_id: z.string().nullable().optional(),
  task_type: z.string().nullable().optional(),
  session_id: z.string().nullable().optional(),
  steps: z.array(traceStepSchema),
}).passthrough()

/** 轨迹统计。 */
export const traceStatsSchema = z.object({
  total_steps: z.number(),
  tool_calls: z.number(),
  thoughts: z.number(),
  findings: z.number(),
  conclusions: z.number(),
  duration_ms: z.number().nullable().optional(),
  tokens_input: z.number(),
  tokens_output: z.number(),
  tool_distribution: z.record(z.string(), z.number()),
}).passthrough()

/** GET /trace/for-finding 响应（按 finding 关联各阶段 session 轨迹 + 统计 + 故事线）。 */
export const trajectorySchema = z.object({
  stages: z.object({
    preprocess: z.array(traceStageSchema).optional(),
    detect: z.array(traceStageSchema),
    mine: z.array(traceStageSchema),
    deepmine: z.array(traceStageSchema).optional(),
    verify: z.array(traceStageSchema),
  }),
  stats: traceStatsSchema,
  story: z.array(z.string()).optional(),
}).passthrough()

export type Trajectory = z.infer<typeof trajectorySchema>

/** POST /compare/trace：跨模型同一 gt 的挖掘轨迹对比（每 report 一 run）。 */
export const trajectoryCompareRunSchema = z.object({
  report_name: z.string(),
  display_label: z.string().optional(),
  status: z.enum(['tp', 'fn', 'unavailable']),
  trajectory: trajectorySchema.optional(),
  reason: z.string().optional(),
}).passthrough()

export const trajectoryCompareSchema = z.object({
  gt_id: z.string(),
  runs: z.array(trajectoryCompareRunSchema),
}).passthrough()

export type TrajectoryCompare = z.infer<typeof trajectoryCompareSchema>
export type TrajectoryCompareRun = z.infer<typeof trajectoryCompareRunSchema>

export type TraceStep = z.infer<typeof traceStepSchema>
export type TraceStage = z.infer<typeof traceStageSchema>
export type TraceStats = z.infer<typeof traceStatsSchema>

// ------------------------------------------------------------------ //
// Inferred types (schema-as-source-of-truth)                          //
// ------------------------------------------------------------------ //

export type PercentileStats = z.infer<typeof percentileStatsSchema>
export type PerfMetrics = z.infer<typeof perfMetricsSchema>
export type ReportData = z.infer<typeof reportDataSchema>
export type LoadReportResponse = z.infer<typeof loadReportResponseSchema>
export type ReportSummary = z.infer<typeof reportSummarySchema>
export type VulnSummary = z.infer<typeof vulnSummarySchema>
export type ListReportsResponse = z.infer<typeof listReportsResponseSchema>
export type ContentBlock = z.infer<typeof contentBlockSchema>
export type ToolCall = z.infer<typeof toolCallSchema>
export type ChatMessage = z.infer<typeof chatMessageSchema>
export type AgentTraceEvent = z.infer<typeof agentTraceEventSchema>
export type AgentTrace = z.infer<typeof agentTraceSchema>
export type PredictionRow = z.infer<typeof predictionRowSchema>
export type PredictionsResponse = z.infer<typeof predictionsResponseSchema>
export type ScanResponse = z.infer<typeof scanResponseSchema>
export type AnalysisResponse = z.infer<typeof analysisResponseSchema>
export type FnAdvice = z.infer<typeof fnAdviceSchema>
export type FnAdviceResponse = z.infer<typeof fnAdviceResponseSchema>
export type FnAdviceProgress = z.infer<typeof fnAdviceProgressSchema>
export type FnAdviceInvokeResponse = z.infer<typeof fnAdviceInvokeResponseSchema>
export type FnAdviceStopResponse = z.infer<typeof fnAdviceStopResponseSchema>
