import { useEffect, useId, useRef, useState, type KeyboardEvent, type SyntheticEvent } from 'react'
import { useLocale } from '@/contexts/LocaleContext'
import { listBenchmarks } from '@/api/eval'
import Button from '@/components/ui/Button'
import Field from '@/components/ui/Field'
import { inputClass } from '@/components/ui/formStyles'
import { validateNumeric, FORM_MESSAGE_KEYS } from '@/domain/form/validation'
import { useFormErrors } from '@/hooks/useFormErrors'

interface Props {
  onSubmit: (config: Record<string, unknown>) => void
  disabled?: boolean
  initialDataset?: string
}

/** Stable field ids (label/error/focus targets). */
const IDS = {
  projectName: 'eval-projectName',
  datasets: 'eval-datasets',
  modelName: 'eval-modelName',
  maxConcurrency: 'eval-maxConcurrency',
  priority: 'eval-priority',
  phase1Timeout: 'eval-phase1Timeout',
  phase2Timeout: 'eval-phase2Timeout',
  phase3Timeout: 'eval-phase3Timeout',
  turingBaseUrl: 'eval-turingBaseUrl',
  pollTimeout: 'eval-pollTimeout',
} as const

const DOM_ORDER: string[] = [
  IDS.projectName, IDS.datasets,
  IDS.modelName, IDS.maxConcurrency, IDS.priority,
  IDS.phase1Timeout, IDS.phase2Timeout, IDS.phase3Timeout,
  IDS.turingBaseUrl, IDS.pollTimeout,
]

const DEFAULT_TURING = 'http://127.0.0.1:8088'

export default function EvalConfigForm({ onSubmit, disabled, initialDataset }: Props) {
  const { t } = useLocale()
  const [projectName, setProjectName] = useState('')
  const [datasets, setDatasets] = useState(initialDataset ?? 'vuln_jeecgboot')
  const [modelName, setModelName] = useState('')
  const [maxConcurrency, setMaxConcurrency] = useState('')
  const [priority, setPriority] = useState('100')
  const [phase1Timeout, setPhase1Timeout] = useState('')
  const [phase2Timeout, setPhase2Timeout] = useState('')
  const [phase3Timeout, setPhase3Timeout] = useState('')
  const [turingBaseUrl, setTuringBaseUrl] = useState(DEFAULT_TURING)
  const [pollTimeout, setPollTimeout] = useState('172800')

  const { setErrors, errorFor: errMsg, clearError: clearErr } = useFormErrors()

  // Dataset autocomplete
  const [benchmarkNames, setBenchmarkNames] = useState<string[]>([])
  const [showSuggestions, setShowSuggestions] = useState(false)
  const [filteredSuggestions, setFilteredSuggestions] = useState<string[]>([])
  const [activeSuggestion, setActiveSuggestion] = useState(-1)
  const datasetInputRef = useRef<HTMLDivElement>(null)
  const datasetListboxId = `${useId()}-dataset-listbox`

  useEffect(() => { if (initialDataset) setDatasets(initialDataset) }, [initialDataset])

  useEffect(() => {
    const controller = new AbortController()
    listBenchmarks(undefined, undefined, controller.signal)
      .then((res) => {
        const names = [...(res.text ?? []).map((b) => b.name), ...(res.multimodal ?? []).map((b) => b.name)]
        setBenchmarkNames(names)
      }).catch(() => {})
    return () => controller.abort()
  }, [])

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (datasetInputRef.current && !datasetInputRef.current.contains(e.target as Node)) setShowSuggestions(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const handleDatasetChange = (val: string) => {
    setDatasets(val)
    const parts = val.split(',')
    const current = parts[parts.length - 1].trim().toLowerCase()
    if (current) {
      const matches = benchmarkNames.filter((n) => n.toLowerCase().includes(current))
      setFilteredSuggestions(matches.slice(0, 8))
      setShowSuggestions(matches.length > 0)
      setActiveSuggestion(matches.length > 0 ? 0 : -1)
    } else {
      setShowSuggestions(false)
      setActiveSuggestion(-1)
    }
    clearErr(IDS.datasets)
  }

  const selectSuggestion = (name: string) => {
    const parts = datasets.split(',').map((s) => s.trim())
    parts[parts.length - 1] = name
    setDatasets(parts.join(', '))
    setShowSuggestions(false)
    setActiveSuggestion(-1)
    clearErr(IDS.datasets)
  }

  const handleDatasetKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape' && showSuggestions) { event.preventDefault(); setShowSuggestions(false); setActiveSuggestion(-1); return }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      if (filteredSuggestions.length === 0) return
      event.preventDefault()
      setShowSuggestions(true)
      setActiveSuggestion((current) => event.key === 'ArrowDown' ? Math.min(Math.max(current, -1) + 1, filteredSuggestions.length - 1) : Math.max(current <= 0 ? 0 : current - 1, 0))
      return
    }
    if (event.key === 'Enter' && showSuggestions && activeSuggestion >= 0) { event.preventDefault(); selectSuggestion(filteredSuggestions[activeSuggestion]) }
  }

  const handleSubmit = (e: SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault()
    const newErrors: Record<string, string> = {}
    if (!projectName.trim()) newErrors[IDS.projectName] = FORM_MESSAGE_KEYS.required
    if (!datasets.trim()) newErrors[IDS.datasets] = FORM_MESSAGE_KEYS.required

    const numericChecks: Array<{ id: string; value: string; min?: number }> = [
      { id: IDS.maxConcurrency, value: maxConcurrency, min: 1 },
      { id: IDS.priority, value: priority, min: 0 },
      { id: IDS.phase1Timeout, value: phase1Timeout, min: 0 },
      { id: IDS.phase2Timeout, value: phase2Timeout, min: 0 },
      { id: IDS.phase3Timeout, value: phase3Timeout, min: 0 },
      { id: IDS.pollTimeout, value: pollTimeout, min: 1 },
    ]
    for (const check of numericChecks) {
      if (check.value.trim() === '') continue
      const err = validateNumeric(Number(check.value), check.min)
      if (err) newErrors[check.id] = err.messageKey
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      const firstInvalid = DOM_ORDER.find((id) => newErrors[id])
      if (firstInvalid) requestAnimationFrame(() => document.getElementById(firstInvalid)?.focus())
      return
    }
    setErrors({})

    const scan_config: Record<string, unknown> = {
      project_name: projectName.trim(),
      model_name: modelName.trim(),
      max_concurrency: maxConcurrency.trim(),
      priority: priority.trim() || '100',
      phase1_timeout: phase1Timeout.trim(),
      phase2_timeout: phase2Timeout.trim(),
      phase3_timeout: phase3Timeout.trim(),
      turing_base_url: turingBaseUrl.trim() || DEFAULT_TURING,
      timeout: pollTimeout ? Number(pollTimeout) : 120,
    }
    onSubmit({
      datasets: datasets.split(',').map((s) => s.trim()).filter(Boolean),
      scan_config,
    })
  }

  const textField = (
    id: string,
    labelKey: string,
    value: string,
    onChange: (v: string) => void,
    opts: { type?: string; placeholder?: string; min?: number; required?: boolean } = {},
  ) => (
    <Field id={id} name={id} labelKey={labelKey} error={errMsg(id)} required={opts.required}>
      {(aria) => (
        <input
          {...aria}
          type={opts.type ?? 'text'}
          min={opts.min}
          value={value}
          onChange={(e) => { onChange(e.target.value); clearErr(id) }}
          className={inputClass(errMsg(id))}
          placeholder={opts.placeholder}
        />
      )}
    </Field>
  )

  return (
    <form onSubmit={handleSubmit} className="space-y-4" noValidate>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Datasets with autocomplete */}
        <Field id={IDS.datasets} name="datasets" labelKey="eval.datasets" required error={errMsg(IDS.datasets)} autoComplete="off" className="relative">
          {(aria) => (
            <div ref={datasetInputRef}>
              <input
                {...aria}
                type="text"
                value={datasets}
                onChange={(e) => handleDatasetChange(e.target.value)}
                onFocus={() => { if (filteredSuggestions.length) setShowSuggestions(true) }}
                onKeyDown={handleDatasetKeyDown}
                role="combobox"
                aria-autocomplete="list"
                aria-expanded={showSuggestions}
                aria-controls={datasetListboxId}
                aria-activedescendant={showSuggestions && activeSuggestion >= 0 ? `${datasetListboxId}-option-${activeSuggestion}` : undefined}
                className={inputClass(errMsg(IDS.datasets))}
                placeholder="vuln_jeecgboot"
              />
              {showSuggestions && (
                <div id={datasetListboxId} role="listbox" className="absolute z-50 left-0 right-0 mt-1 rounded-[var(--radius-sm)] border border-[var(--border-md)] bg-[var(--bg-card)] shadow-[var(--shadow)] overflow-hidden max-h-48 overflow-y-auto">
                  {filteredSuggestions.map((name, index) => (
                    <button
                      key={name}
                      id={`${datasetListboxId}-option-${index}`}
                      type="button"
                      role="option"
                      aria-selected={index === activeSuggestion}
                      onMouseEnter={() => setActiveSuggestion(index)}
                      onClick={() => selectSuggestion(name)}
                      className={`w-full min-h-11 text-left px-3 py-2 text-sm text-[var(--text)] transition-colors cursor-pointer ${index === activeSuggestion ? 'bg-[var(--bg-card2)]' : 'hover:bg-[var(--bg-card2)]'}`}
                    >
                      {name}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </Field>

        {textField(IDS.projectName, 'eval.scanConfig.projectName', projectName, setProjectName, { placeholder: t('eval.scanConfig.projectNamePlaceholder'), required: true })}
        {textField(IDS.modelName, 'eval.scanConfig.modelName', modelName, setModelName, { placeholder: t('eval.scanConfig.modelNamePlaceholder') })}
        {textField(IDS.maxConcurrency, 'eval.scanConfig.maxConcurrency', maxConcurrency, setMaxConcurrency, { type: 'number', min: 1, placeholder: '4' })}
        {textField(IDS.priority, 'eval.scanConfig.priority', priority, setPriority, { type: 'number', min: 0 })}
        {textField(IDS.phase1Timeout, 'eval.scanConfig.phase1Timeout', phase1Timeout, setPhase1Timeout, { type: 'number', min: 0, placeholder: t('eval.scanConfig.seconds') })}
        {textField(IDS.phase2Timeout, 'eval.scanConfig.phase2Timeout', phase2Timeout, setPhase2Timeout, { type: 'number', min: 0, placeholder: t('eval.scanConfig.seconds') })}
        {textField(IDS.phase3Timeout, 'eval.scanConfig.phase3Timeout', phase3Timeout, setPhase3Timeout, { type: 'number', min: 0, placeholder: t('eval.scanConfig.seconds') })}
        {textField(IDS.turingBaseUrl, 'eval.scanConfig.turingBaseUrl', turingBaseUrl, setTuringBaseUrl, { placeholder: DEFAULT_TURING })}
        {textField(IDS.pollTimeout, 'eval.scanConfig.pollTimeout', pollTimeout, setPollTimeout, { type: 'number', min: 1 })}
      </div>

      <Button type="submit" variant="primary" disabled={disabled} className="btn-glow">
        {t('eval.startEval')}
      </Button>
    </form>
  )
}
