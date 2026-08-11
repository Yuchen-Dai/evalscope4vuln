import { z } from 'zod'

export const dataFrameResponseSchema = z.object({
  columns: z.array(z.string()),
  data: z.array(z.record(z.string(), z.unknown())),
})

export const logResponseSchema = z.object({
  text: z.string(),
  head_line: z.number(),
  tail_line: z.number(),
  total_lines: z.number(),
})

export const taskStatusResponseSchema = z.object({
  status: z.string(),
  task_id: z.string(),
})

export const configResponseSchema = z.object({
  outputs_root: z.string(),
})

/** 全局 judge 模型配置（GET /settings/judge；api_key 不回明文，仅 has_api_key）。 */
export const judgeConfigSchema = z.object({
  api_url: z.string(),
  model_id: z.string(),
  has_api_key: z.boolean(),
})

/** POST /settings/judge 保存响应。 */
export const judgeConfigSaveResponseSchema = z.object({
  status: z.string(),
  has_api_key: z.boolean(),
})

export type DataFrameResponse = z.infer<typeof dataFrameResponseSchema>
export type LogResponse = z.infer<typeof logResponseSchema>
export type TaskStatusResponse = z.infer<typeof taskStatusResponseSchema>
export type JudgeConfig = z.infer<typeof judgeConfigSchema>
export type JudgeConfigSaveResponse = z.infer<typeof judgeConfigSaveResponseSchema>
