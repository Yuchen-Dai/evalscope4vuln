import { useLocale } from '@/contexts/LocaleContext'
import { useQueryParams } from '@/hooks/useQueryParams'
import EvalConfigForm from '@/components/eval/EvalConfigForm'
import TaskRunnerPage from '@/components/tasks/TaskRunnerPage'
import { submitEvalTask, stopEvalTask, getEvalProgress, getEvalLog, getEvalReportUrl, getEvalTasks } from '@/api/eval'

export default function EvalTaskPage() {
  const { t } = useLocale()
  const queryParams = useQueryParams()
  const initialDataset = queryParams.get('dataset')

  return (
    <TaskRunnerPage
      title={t('eval.title')}
      configTitle={t('eval.config')}
      statusTitle={t('eval.status')}
      readyLabel={t('eval.ready')}
      submitTask={submitEvalTask}
      stopTask={stopEvalTask}
      getProgress={getEvalProgress}
      getLog={getEvalLog}
      getReportUrl={getEvalReportUrl}
      getTasks={getEvalTasks}
      renderForm={({ onSubmit, disabled }) => (
        <EvalConfigForm onSubmit={onSubmit} disabled={disabled} initialDataset={initialDataset} />
      )}
    />
  )
}
