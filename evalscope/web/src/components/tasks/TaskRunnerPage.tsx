import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import type { EvalInvokeResponse, LogResponse, ProgressResponse } from '@/api/types'
import { usePolling } from '@/hooks/usePolling'
import Card from '@/components/ui/Card'
import TaskMonitor from '@/components/eval/TaskMonitor'

interface FormRenderProps {
  onSubmit: (config: Record<string, unknown>) => Promise<void>
  disabled: boolean
}

interface TaskRunnerPageProps {
  idPrefix: string
  title: string
  configTitle: string
  statusTitle: string
  readyLabel: string
  renderForm: (props: FormRenderProps) => ReactNode
  submitTask: (config: Record<string, unknown>, taskId: string) => Promise<EvalInvokeResponse>
  stopTask: (taskId: string) => Promise<unknown>
  getProgress: (taskId: string) => Promise<ProgressResponse>
  getLog: (taskId: string, tailLine: number) => Promise<LogResponse>
  getReportUrl: (taskId: string) => string
}

function createTaskId(prefix: string): string {
  return `${prefix}_${Date.now()}`
}

// 持久化正在运行的 task_id，使刷新页面后能恢复进度/日志观察（任务在后端 spawn 子进程继续跑）
function storageKey(prefix: string) {
  return `vulnbench:running-task:${prefix}`
}
function loadRunningTaskId(prefix: string): string | null {
  try {
    return localStorage.getItem(storageKey(prefix))
  } catch {
    return null
  }
}
function saveRunningTaskId(prefix: string, taskId: string) {
  try {
    localStorage.setItem(storageKey(prefix), taskId)
  } catch { /* ignore quota */ }
}
function clearRunningTaskId(prefix: string) {
  try {
    localStorage.removeItem(storageKey(prefix))
  } catch { /* ignore */ }
}

export default function TaskRunnerPage({
  idPrefix,
  title,
  configTitle,
  statusTitle,
  readyLabel,
  renderForm,
  submitTask,
  stopTask,
  getProgress,
  getLog,
  getReportUrl,
}: TaskRunnerPageProps) {
  // 刷新恢复：若 localStorage 有正在运行的 task_id，初始化为它
  const [taskId, setTaskId] = useState<string | null>(() => loadRunningTaskId(idPrefix))
  const [running, setRunning] = useState<boolean>(() => !!loadRunningTaskId(idPrefix))
  const [result, setResult] = useState<EvalInvokeResponse | null>(null)
  const [logText, setLogText] = useState('')
  const [logLine, setLogLine] = useState(0)
  const [progress, setProgress] = useState(0)

  const markCompleted = useCallback((id: string) => {
    setRunning(false)
    setResult({ status: 'ok', task_id: id })   // 构造完成 result，让 TaskMonitor 显示 Completed + report 链接
    clearRunningTaskId(idPrefix)
  }, [idPrefix])

  // 刷新恢复时：查一次 progress，判断是仍在运行还是已完成（刷新前就跑完了）
  useEffect(() => {
    const id = loadRunningTaskId(idPrefix)
    if (!id) return
    getProgress(id)
      .then((p) => {
        if ((p.percent ?? 0) >= 100) {
          markCompleted(id)
        }
        // 否则保持 running=true，usePolling 继续轮询 progress/log
      })
      .catch(() => {
        // progress 查不到（任务已被清理）→ 视为结束
        setRunning(false)
        clearRunningTaskId(idPrefix)
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const handleSubmit = async (config: Record<string, unknown>) => {
    const id = createTaskId(idPrefix)
    setTaskId(id)
    setRunning(true)
    setLogText('')
    setLogLine(0)
    setProgress(0)
    setResult(null)
    saveRunningTaskId(idPrefix, id)    // 持久化，刷新可恢复
    try {
      const res = await submitTask(config, id)
      setResult(res)
      clearRunningTaskId(idPrefix)     // invoke 返回（完成）→ 清
    } catch (error) {
      setResult({ status: 'error', task_id: id, error: String(error) })
      clearRunningTaskId(idPrefix)
    } finally {
      setRunning(false)
    }
  }

  const handleStop = async () => {
    if (!taskId) return
    try {
      await stopTask(taskId)
    } catch {
      // backend unavailable
    }
    setRunning(false)
    clearRunningTaskId(idPrefix)
    setResult({ status: 'stopped', task_id: taskId })
  }

  const progressFn = useCallback(async () => {
    if (!taskId) throw new Error('no task')
    return getProgress(taskId)
  }, [getProgress, taskId])

  const logFn = useCallback(async () => {
    if (!taskId) throw new Error('no task')
    return getLog(taskId, logLine)
  }, [getLog, logLine, taskId])

  usePolling<ProgressResponse>({
    fn: progressFn,
    enabled: running && !!taskId,
    interval: 5000,
    onData: (data) => {
      setProgress(data.percent ?? 0)
      if ((data.percent ?? 0) >= 100 && taskId) markCompleted(taskId)
    },
  })

  usePolling<LogResponse>({
    fn: logFn,
    enabled: running && !!taskId,
    interval: 5000,
    onData: (data) => {
      if (!data.text) return
      setLogText((previous) => previous + data.text)
      setLogLine(data.tail_line)
    },
  })

  const reportUrl = useMemo(() => (taskId ? getReportUrl(taskId) : null), [getReportUrl, taskId])

  return (
    <div className="page-enter">
      <h1 className="text-xl font-semibold mb-6">{title}</h1>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title={configTitle}>{renderForm({ onSubmit: handleSubmit, disabled: running })}</Card>
        <Card title={statusTitle}>
          <TaskMonitor
            running={running}
            progress={progress}
            logText={logText}
            result={result}
            reportUrl={reportUrl}
            readyLabel={readyLabel}
            onStop={handleStop}
          />
        </Card>
      </div>
    </div>
  )
}
