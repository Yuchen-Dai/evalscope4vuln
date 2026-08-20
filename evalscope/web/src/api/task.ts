import { apiPostValidated, apiValidated } from './client'
import {
  evalInvokeResponseSchema,
  logResponseSchema,
  progressResponseSchema,
  taskStatusResponseSchema,
  tasksResponseSchema,
} from './schemas'
import type { EvalInvokeResponse, LogResponse, ProgressResponse, TaskStatusResponse } from './types'
import type { TasksResponse } from './schemas/eval.schema'

type TaskScope = 'eval' | 'perf'

export function createTaskApi(scope: TaskScope) {
  const basePath = `/api/v1/${scope}`

  return {
    submit(
      payload: Record<string, unknown>,
      signal?: AbortSignal,
    ): Promise<EvalInvokeResponse> {
      // task_id is generated server-side and returned in the response body.
      return apiPostValidated(`${basePath}/invoke`, payload, evalInvokeResponseSchema, { signal })
    },

    progress(taskId: string, signal?: AbortSignal): Promise<ProgressResponse> {
      return apiValidated(`${basePath}/progress`, progressResponseSchema, {
        params: { task_id: taskId },
        signal,
      })
    },

    log(
      taskId: string,
      startLine?: number,
      page = 500,
      signal?: AbortSignal,
    ): Promise<LogResponse> {
      const params: Record<string, string> = { task_id: taskId, page: String(page) }
      if (startLine !== undefined) params.start_line = String(startLine)
      return apiValidated(`${basePath}/log`, logResponseSchema, { params, signal })
    },

    reportUrl(taskId: string): string {
      return `${basePath}/report?task_id=${encodeURIComponent(taskId)}`
    },

    stop(taskId: string, signal?: AbortSignal): Promise<TaskStatusResponse> {
      return apiPostValidated(
        `${basePath}/stop`,
        {},
        taskStatusResponseSchema,
        { params: { task_id: taskId }, signal },
      )
    },

    tasks(signal?: AbortSignal): Promise<TasksResponse> {
      return apiValidated(`${basePath}/tasks`, tasksResponseSchema, { signal })
    },
  }
}
