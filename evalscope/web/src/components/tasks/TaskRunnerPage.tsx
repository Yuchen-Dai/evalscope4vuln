import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import type { EvalInvokeResponse, LogResponse, ProgressResponse } from '@/api/types'
import type { TaskEntry } from '@/api/schemas/eval.schema'
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
  getTasks: (signal?: AbortSignal) => Promise<{ tasks: TaskEntry[] }>
}

function createTaskId(prefix: string): string {
  return `${prefix}_${Date.now()}`
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
  getTasks,
}: TaskRunnerPageProps) {
  const [taskId, setTaskId] = useState<string | null>(null)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<EvalInvokeResponse | null>(null)
  const [logText, setLogText] = useState('')
  const [logLine, setLogLine] = useState(0)
  const [progress, setProgress] = useState(0)
  const [tasks, setTasks] = useState<TaskEntry[]>([])

  const markCompleted = useCallback((id: string) => {
    setRunning(false)
    setResult({ status: 'ok', task_id: id })
    // 任务完成时拉一次增量日志（确保最后的日志行不丢）
    getLog(id, logLine).then((data) => {
      if (data.text) {
        setLogText((prev) => prev + data.text)
        setLogLine(data.tail_line)
      }
    }).catch(() => {})
  }, [getLog, logLine])

  // 任务列表：定期从服务端拉（多用户全局共享，刷新/换终端都能看到）
  const refreshTasks = useCallback(async (signal?: AbortSignal) => {
    try {
      setTasks((await getTasks(signal)).tasks)
    } catch {
      /* ignore */
    }
  }, [getTasks])

  useEffect(() => {
    const c = new AbortController()
    refreshTasks(c.signal)
    const timer = setInterval(() => refreshTasks(), 5000)
    return () => {
      c.abort()
      clearInterval(timer)
    }
  }, [refreshTasks])

  const handleSubmit = async (config: Record<string, unknown>) => {
    const id = createTaskId(idPrefix)
    setTaskId(id)
    setRunning(true)
    setLogText('')
    setLogLine(0)
    setProgress(0)
    setResult(null)
    try {
      await submitTask(config, id)   // 异步 invoke，立即返回 running（不阻塞）
      refreshTasks()                 // 列表刷新（含新任务）
    } catch (error) {
      setResult({ status: 'error', task_id: id, error: String(error) })
      setRunning(false)
    }
  }

  const selectTask = (id: string) => {
    setTaskId(id)
    setLogText('')
    setLogLine(0)
    setProgress(0)
    setResult(null)
    // 查一次 progress 判断是运行中还是已完成
    getProgress(id)
      .then(async (p) => {
        if ((p.percent ?? 0) >= 100) {
          setRunning(false)
          markCompleted(id)
          // 已完成任务：拉一次完整日志（从头，因为日志轮询不会自动启动）
          try {
            const log = await getLog(id, 0)
            if (log.text) { setLogText(log.text); setLogLine(log.tail_line) }
          } catch { /* ignore */ }
        } else {
          setRunning(true)
        }
      })
      .catch(() => setRunning(false))
  }

  const handleStop = async () => {
    if (!taskId) return
    try {
      await stopTask(taskId)
    } catch {
      // backend unavailable
    }
    setRunning(false)
    setResult({ status: 'stopped', task_id: taskId })
    refreshTasks()
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
      if ((data.percent ?? 0) >= 100 && taskId) {
        markCompleted(taskId)
        refreshTasks()
      }
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
        <div className="space-y-6">
          <Card title={configTitle}>{renderForm({ onSubmit: handleSubmit, disabled: running })}</Card>
          <Card title="Tasks">
            <ul className="divide-y divide-[var(--border)] max-h-72 overflow-y-auto">
              {tasks.length === 0 && (
                <li className="py-4 text-center text-sm text-[var(--text-muted)]">No tasks</li>
              )}
              {tasks.map((t) => (
                <li key={t.task_id}>
                  <button
                    onClick={() => selectTask(t.task_id)}
                    className={`w-full text-left px-3 py-2 text-sm transition-colors hover:bg-[var(--bg-card2)] ${taskId === t.task_id ? 'bg-[var(--bg-card2)]' : ''}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate">
                        {t.model && <span className="font-medium">{t.model}</span>}
                        {t.dataset && <span className="ml-1 text-xs text-[var(--text-muted)]">{t.dataset}</span>}
                      </span>
                      <span
                        className={`shrink-0 ${t.status === 'running' ? 'text-[var(--accent)]' : t.status === 'error' ? 'text-[var(--danger)]' : 'text-[var(--text-muted)]'}`}
                      >
                        {t.status} {Math.round(t.percent)}%
                      </span>
                    </div>
                    <div className="text-xs text-[var(--text-muted)] truncate">{t.updated_at}</div>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
        </div>
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
