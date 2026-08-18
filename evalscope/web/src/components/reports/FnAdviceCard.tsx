/**
 * FN 漏报分析结果只读卡片：结构化建议（category/stages/reasoning/suggestions/summary）
 * + 相关文件折叠 + 错误行 + 旧缓存纯文本回退。自 VulnFindingsView.FnAdviceBlock 抽取
 * （触发按钮移除 —— 分析入口统一收敛到 FnAnalysisTab）。
 */
import { useState, type ReactNode } from 'react'
import { useLocale } from '@/contexts/LocaleContext'
import type { FnAdvice } from '@/api/types'

/** advice_structured 的已知字段（后端 fn_advisor.extract_structured_advice / MCP staging 输出）。 */
interface FnAdviceStructured {
  category?: unknown
  stages?: unknown
  reasoning?: unknown
  suggestions?: unknown
  summary?: unknown
}

/** 结构化字段安全取值：字符串 strip；数组元素转非空字符串列表。 */
const asStr = (v: unknown): string => (typeof v === 'string' ? v.trim() : '')
const asStrList = (v: unknown): string[] =>
  Array.isArray(v) ? v.map((x) => (typeof x === 'string' ? x.trim() : '')).filter(Boolean) : []

export default function FnAdviceCard({ advice, title }: { advice?: FnAdvice; title?: ReactNode }) {
  const { t } = useLocale()
  const [showFiles, setShowFiles] = useState(false)
  const files = advice?.related_files ?? []
  const st = (advice?.advice_structured ?? null) as FnAdviceStructured | null
  const stCategory = st ? asStr(st.category) : ''
  const stStages = st ? asStrList(st.stages) : []
  const stReasoning = st ? asStr(st.reasoning) : ''
  const stSuggestions = st ? asStrList(st.suggestions) : []
  const stSummary = st ? asStr(st.summary) : ''
  const structuredOk = !!st && !!(stCategory || stStages.length || stReasoning || stSuggestions.length || stSummary)
  if (!advice) return null
  return (
    <div className="pt-2 border-t border-[var(--border)] flex flex-col gap-2">
      {title && <div className="text-xs font-medium text-[var(--text-muted)]">{title}</div>}
      <div className="flex items-center gap-2">
        {advice.status === 'ok' && advice.related_sessions != null && (
          <span className="text-[10px] text-[var(--text-muted)]">
            {t('vuln.fnRelatedSessions', { sessions: advice.related_sessions })}
          </span>
        )}
        {advice.status === 'ok' && files.length > 0 && (
          <button
            onClick={() => setShowFiles(!showFiles)}
            className="text-[10px] text-[var(--accent)] hover:underline cursor-pointer"
          >
            {t('vuln.fnRelatedFiles', { n: files.length })}{showFiles ? ' ▾' : ' ▸'}
          </button>
        )}
      </div>
      {advice.status === 'error' && (
        <div className="text-xs text-[var(--danger)] break-all">⚠ {advice.error}</div>
      )}
      {advice.status === 'ok' && files.length > 0 && showFiles && (
        <div className="flex flex-col gap-0.5">
          {files.map((fp, i) => (
            <span key={i} className="text-[11px] font-mono text-[var(--text-muted)] truncate" title={fp}>
              {fp}
            </span>
          ))}
        </div>
      )}
      {advice.status === 'ok' && structuredOk && (
        <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--bg-deep)] flex flex-col gap-2 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] text-[var(--text-muted)]">{t('vuln.fnCategory')}</span>
            {stCategory && (
              <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-[var(--danger)] text-white">{stCategory}</span>
            )}
            {stStages.length > 0 && (
              <span className="flex flex-wrap items-center gap-1">
                <span className="text-[10px] text-[var(--text-muted)]">{t('vuln.fnStages')}</span>
                {stStages.map((s, i) => (
                  <span key={i} className="text-[10px] px-1.5 py-0.5 rounded border border-[var(--border)] bg-[var(--bg-card2)] font-mono">{s}</span>
                ))}
              </span>
            )}
          </div>
          {stReasoning && (
            <div>
              <div className="text-[10px] font-medium text-[var(--text-muted)] mb-0.5">{t('vuln.fnReasoning')}</div>
              <p className="whitespace-pre-wrap break-words leading-relaxed">{stReasoning}</p>
            </div>
          )}
          {stSuggestions.length > 0 && (
            <div>
              <div className="text-[10px] font-medium text-[var(--text-muted)] mb-0.5">{t('vuln.fnSuggestions')}</div>
              <ul className="flex flex-col gap-1 list-disc pl-4">
                {stSuggestions.map((s, i) => <li key={i} className="break-words leading-relaxed">{s}</li>)}
              </ul>
            </div>
          )}
          {stSummary && (
            <div className="pt-1 border-t border-[var(--border)]">
              <span className="text-[var(--text-muted)] mr-1">{t('vuln.fnSummary')}:</span>
              <span className="font-medium">{stSummary}</span>
            </div>
          )}
        </div>
      )}
      {advice.status === 'ok' && advice.advice && !structuredOk && (
        <pre className="p-3 rounded-[var(--radius-sm)] bg-[var(--bg-deep)] text-xs whitespace-pre-wrap break-words max-h-[400px] overflow-y-auto">{advice.advice}</pre>
      )}
    </div>
  )
}
