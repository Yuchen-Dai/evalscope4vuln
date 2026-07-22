import EvalTaskPage from './EvalTaskPage'

/**
 * Tasks 页 — 漏洞测评任务（Evaluation）。原 Performance tab 已移除（图灵平台用不到）。
 */
export default function TasksPage() {
  return (
    <div className="page-enter flex flex-col gap-4">
      <EvalTaskPage />
    </div>
  )
}
