// ------------------------------------------------------------------ //
// "reports" API domain types                                          //
// ------------------------------------------------------------------ //
//
// All endpoint response types are derived from runtime zod schemas. This barrel
// preserves the stable `@/api/types` import path while keeping the schemas as
// the single compile-time/runtime source of truth.

export type {
  // Report score tree
  PercentileStats,
  PerfMetrics,
  // Report payloads
  ReportData,
  LoadReportResponse,
  // Report list / summary
  ReportSummary,
  ListReportsResponse,
  // Prediction rows (chat messages + agent trace)
  ContentBlock,
  ToolCall,
  ChatMessage,
  AgentTraceEvent,
  AgentTrace,
  PredictionRow,
  PredictionsResponse,
  ScanResponse,
  AnalysisResponse,
  // FN 漏报 LLM-as-judge 路径分析
  FnAdvice,
  FnAdviceResponse,
  FnAdviceProgress,
  FnAdviceInvokeResponse,
  FnAdviceStopResponse,
  // 挖掘轨迹展示
  Trajectory,
  TraceStep,
  TraceStage,
  TraceStats,
} from '@/api/schemas/reports.schema'
