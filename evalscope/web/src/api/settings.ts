import { apiPostValidated, apiValidated } from './client'
import { judgeConfigSaveResponseSchema, judgeConfigSchema } from './schemas'
import type { JudgeConfig, JudgeConfigSaveResponse } from './types'

const BASE = '/api/v1/settings'

/** 读取全局 judge 模型配置（api_key 不回明文，仅 has_api_key）。 */
export async function getJudgeConfig(signal?: AbortSignal): Promise<JudgeConfig> {
  return apiValidated(`${BASE}/judge`, judgeConfigSchema, { signal })
}

/**
 * 保存全局 judge 模型配置。api_key 留空（undefined）则后端保留旧值；
 * 传非空字符串则更新。
 */
export async function saveJudgeConfig(
  payload: { api_url: string; model_id: string; api_key?: string },
  signal?: AbortSignal,
): Promise<JudgeConfigSaveResponse> {
  return apiPostValidated(`${BASE}/judge`, payload, judgeConfigSaveResponseSchema, { signal })
}
