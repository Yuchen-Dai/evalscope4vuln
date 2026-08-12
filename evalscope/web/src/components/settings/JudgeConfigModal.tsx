import { useEffect, useState } from 'react'
import Modal from '@/components/ui/Modal'
import Button from '@/components/ui/Button'
import { FORM_LABEL_CLASS, inputClass } from '@/components/ui/formStyles'
import { useLocale } from '@/contexts/LocaleContext'
import { getJudgeConfig, saveJudgeConfig } from '@/api/settings'

interface Props {
  open: boolean
  onClose: () => void
}

/**
 * 全局 Judge 模型配置弹窗：用于 FN 漏报路径分析。配置存服务端
 * <outputs_root>/judge_config.json，所有报告共享，评测前后均可配置。
 * api_key 不回显明文，留空保存=保留旧值。
 */
export default function JudgeConfigModal({ open, onClose }: Props) {
  const { t } = useLocale()
  const [apiUrl, setApiUrl] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [modelId, setModelId] = useState('')
  const [hasKey, setHasKey] = useState(false)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)

  // 打开时加载已有配置（api_key 不回显）
  useEffect(() => {
    if (!open) return
    setMsg(null)
    setApiKey('')
    setLoading(true)
    getJudgeConfig()
      .then((c) => { setApiUrl(c.api_url); setModelId(c.model_id); setHasKey(c.has_api_key) })
      .catch((e) => setMsg({ kind: 'error', text: t('eval.judge.loadFailed', { msg: String(e) }) }))
      .finally(() => setLoading(false))
  }, [open, t])

  const handleSave = async () => {
    if (!apiUrl.trim() || !modelId.trim()) {
      setMsg({ kind: 'error', text: t('eval.judge.requiredError') })
      return
    }
    setSaving(true)
    setMsg(null)
    try {
      const payload: { api_url: string; model_id: string; api_key?: string } = {
        api_url: apiUrl.trim(),
        model_id: modelId.trim(),
      }
      // api_key 留空 → 不传 → 后端保留旧值
      if (apiKey.trim()) payload.api_key = apiKey.trim()
      const res = await saveJudgeConfig(payload)
      setHasKey(res.has_api_key)
      setApiKey('')
      setMsg({ kind: 'ok', text: t('eval.judge.saved') })
    } catch (e) {
      setMsg({ kind: 'error', text: t('eval.judge.saveFailed', { msg: String(e) }) })
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={t('eval.judge.title')}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t('eval.judge.cancel')}</Button>
          <Button variant="primary" onClick={handleSave} disabled={saving || loading}>
            {saving ? t('eval.judge.saving') : t('eval.judge.save')}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <p className="text-xs text-[var(--text-muted)]">
          {t('eval.judge.desc')} {t('eval.judge.envPrefix')}{' '}
          <code>VULN_JUDGE_API_URL</code> /{' '}
          <code>VULN_JUDGE_API_KEY</code> / <code>VULN_JUDGE_MODEL</code>。
        </p>
        {loading && <p className="text-xs text-[var(--text-muted)]">{t('eval.judge.loading')}</p>}
        <div>
          <label className={FORM_LABEL_CLASS}>{t('eval.judge.apiUrl')}</label>
          <input
            type="text"
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
            className={inputClass()}
            placeholder="https://.../v1"
            autoComplete="off"
          />
        </div>
        <div>
          <label className={FORM_LABEL_CLASS}>{t('eval.judge.model')}</label>
          <input
            type="text"
            value={modelId}
            onChange={(e) => setModelId(e.target.value)}
            className={inputClass()}
            placeholder="qwen-max"
            autoComplete="off"
          />
        </div>
        <div>
          <label className={FORM_LABEL_CLASS}>{t('eval.judge.apiKey')}</label>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className={inputClass()}
            placeholder={hasKey ? t('eval.judge.keyConfigured') : 'sk-...'}
            autoComplete="off"
          />
        </div>
        {msg && (
          <div className={`text-xs ${msg.kind === 'ok' ? 'text-[var(--success)]' : 'text-[var(--danger)]'}`}>
            {msg.text}
          </div>
        )}
      </div>
    </Modal>
  )
}
