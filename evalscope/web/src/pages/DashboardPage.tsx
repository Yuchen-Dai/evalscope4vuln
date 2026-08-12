import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useReports } from '@/contexts/ReportsContext'
import { useLocale } from '@/contexts/LocaleContext'
import { listReports } from '@/api/reports'
import type { ReportSummary } from '@/api/types'
import Card from '@/components/ui/Card'
import Badge from '@/components/ui/Badge'
import Skeleton from '@/components/ui/Skeleton'
import KpiCard from '@/components/ui/KpiCard'
import ScoreBadge from '@/components/ui/ScoreBadge'
import EmptyState from '@/components/common/EmptyState'
import EmptyStateSystem from '@/components/common/EmptyStateSystem'
import SearchInput from '@/components/ui/SearchInput'
import Pagination from '@/components/ui/Pagination'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { FileText, Cpu, Clock, ChevronRight, Target, ShieldAlert } from 'lucide-react'

// Number of recent runs shown before pagination.
const RECENT_LIMIT = 15

/** Format ISO timestamp to short form MM-DD HH:MM. */
function formatShort(ts: string): string {
  return ts ? ts.replace('T', ' ').slice(5, 16) : ''
}

function RunRow({ report, onClick }: { report: ReportSummary; onClick: () => void }) {
  const { t } = useLocale()
  return (
    <button
      onClick={onClick}
      className="grid min-h-14 w-full grid-cols-[3rem_minmax(0,1fr)_auto_auto] items-center gap-x-2 px-3 py-2 text-left transition-colors hover:bg-[var(--bg-card2)] focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--accent)] md:grid-cols-[3rem_minmax(8rem,1fr)_minmax(10rem,1.5fr)_8rem_7rem_1rem] md:gap-x-3"
    >
      <span
        aria-label={t('dashboard.filter_eval')}
        title={t('dashboard.filter_eval')}
        className="mx-auto flex h-8 w-8 items-center justify-center rounded-[var(--radius-sm)] bg-[var(--accent-dim)] text-[var(--accent)]"
      >
        <FileText size={16} strokeWidth={2} />
      </span>
      <div className="flex flex-col min-w-0 flex-1">
        <span className="type-body-sm text-[var(--text)] break-words">{report.model_name}</span>
        <span className="type-caption-mono text-[var(--text-muted)] break-words md:hidden">{report.dataset_name}</span>
        <span className="type-caption-mono mt-0.5 text-[var(--text-dim)] md:hidden">{formatShort(report.timestamp || '')}</span>
      </div>
      <div className="hidden min-w-0 flex-col md:flex">
        <span className="type-body-sm break-words text-[var(--text)]">{report.dataset_name}</span>
        <span className="type-caption-mono text-[var(--text-muted)]">{report.num_samples} {t('dashboard.samples')}</span>
      </div>
      <span className="type-caption-mono hidden whitespace-nowrap text-[var(--text-muted)] md:block">
        {formatShort(report.timestamp || '')}
      </span>
      <ScoreBadge score={report.score} className="shrink-0 !text-xs !px-2" />
      <ChevronRight size={14} className="text-[var(--text-dim)] shrink-0" />
    </button>
  )
}

export default function DashboardPage() {
  const { t } = useLocale()
  const { rootPath, scanToken } = useReports()
  const navigate = useNavigate()

  const [loading, setLoading] = useState(false)
  const [scanned, setScanned] = useState(false)
  const [reports, setReports] = useState<ReportSummary[]>([])
  const [loadError, setLoadError] = useState('')

  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)

  useEffect(() => {
    if (!rootPath) return
    const controller = new AbortController()
    const load = async () => {
      setLoading(true)
      setLoadError('')
      try {
        const res = await listReports({ rootPath, pageSize: 1000, sortBy: 'time', sortOrder: 'desc', signal: controller.signal })
        if (controller.signal.aborted) return
        setReports(res.reports)
      } catch (e) {
        if (controller.signal.aborted) return
        setLoadError(e instanceof Error ? e.message : t('common.loadError'))
      } finally {
        setScanned(true)
        setLoading(false)
      }
    }
    load()
    return () => { controller.abort() }
  }, [rootPath, scanToken, t])

  const filteredItems = useMemo<ReportSummary[]>(() => {
    const q = query.trim().toLowerCase()
    const sorted = [...reports].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
    if (!q) return sorted
    return sorted.filter((r) =>
      (r.model_name || '').toLowerCase().includes(q) ||
      (r.dataset_name || '').toLowerCase().includes(q),
    )
  }, [reports, query])

  const totalPages = Math.max(1, Math.ceil(filteredItems.length / RECENT_LIMIT))
  const safePage = Math.min(page, totalPages)
  const visibleItems = filteredItems.slice((safePage - 1) * RECENT_LIMIT, safePage * RECENT_LIMIT)

  const kpi = useMemo(() => {
    const models = new Set<string>()
    // Vuln-mining aggregation: only reports carrying vuln_summary contribute.
    // Non-vuln / legacy reports are skipped so the KPIs degrade to hidden.
    const vulnReports = reports.filter((r) => r.vuln_summary)
    let totalFn = 0
    let recallSum = 0
    reports.forEach((r) => {
      models.add(r.model_name)
      if (r.vuln_summary) {
        totalFn += r.vuln_summary.fn
        recallSum += r.vuln_summary.recall
      }
    })
    const latestTs = reports.reduce((m, r) => ((r.timestamp || '').localeCompare(m) > 0 ? r.timestamp || '' : m), '')
    return {
      evals: reports.length,
      models: models.size,
      latest: latestTs ? formatShort(latestTs) : t('dashboard.neverText'),
      hasVuln: vulnReports.length > 0,
      totalFn,
      avgRecall: vulnReports.length ? recallSum / vulnReports.length : null,
    }
  }, [reports, t])

  const openItem = (report: ReportSummary) => {
    navigate(`/reports/${encodeURIComponent(report.name)}?root_path=${encodeURIComponent(rootPath)}`)
  }

  const hasData = scanned && reports.length > 0

  return (
    <div className="mx-auto flex min-h-0 w-full max-w-7xl flex-col gap-5">
      {loadError && <ErrorAlert className="rounded-[var(--radius-sm)]">{loadError}</ErrorAlert>}

      {/* ── KPI Cards ── */}
      {loading && !scanned ? (
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] p-5">
              <Skeleton width={40} height={40} className="mb-3" />
              <Skeleton width={60} height={28} className="mb-1" />
              <Skeleton width={100} height={14} />
            </div>
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
          <KpiCard
            icon={<FileText size={18} strokeWidth={2} />}
            value={String(kpi.evals)}
            label={t('dashboard.totalEvaluations')}
            gradient="var(--kpi-grad-0)"
            delay={0}
            onClick={() => navigate('/reports')}
          />
          <KpiCard
            icon={<Cpu size={18} strokeWidth={2} />}
            value={String(kpi.models)}
            label={t('dashboard.modelsEvaluated')}
            gradient="var(--kpi-grad-2)"
            delay={120}
          />
          <KpiCard
            icon={<Clock size={18} strokeWidth={2} />}
            value={kpi.latest}
            label={t('dashboard.latestRun')}
            gradient="var(--kpi-grad-3)"
            delay={180}
          />
          {/* Vuln-dimension KPIs — only rendered when at least one run exposes
              vuln_summary (TP/FP/FN). Hidden on non-vuln / legacy installations. */}
          {kpi.hasVuln && (
            <KpiCard
              icon={<Target size={18} strokeWidth={2} />}
              value={kpi.avgRecall != null ? `${Math.round(kpi.avgRecall * 100)}%` : t('dashboard.neverText')}
              label={t('dashboard.avgRecall')}
              gradient="var(--kpi-grad-1)"
              delay={210}
            />
          )}
          {kpi.hasVuln && (
            <KpiCard
              icon={<ShieldAlert size={18} strokeWidth={2} />}
              value={String(kpi.totalFn)}
              label={t('dashboard.totalMissed')}
              gradient="var(--kpi-grad-2)"
              delay={240}
            />
          )}
        </div>
      )}

      {/* ── Recent Runs ── */}
      {loading && !scanned ? (
        <Card title={t('dashboard.recentRuns')}>
          <Skeleton lines={8} height={14} />
        </Card>
      ) : hasData ? (
        <Card title={t('dashboard.recentRuns')} badge={<Badge>{filteredItems.length}</Badge>}>
          <div className="mb-2 flex flex-col gap-2 sm:flex-row sm:items-center">
            <SearchInput
              value={query}
              onChange={(v) => { setQuery(v); setPage(1) }}
              placeholder={t('dashboard.searchPlaceholder')}
              className="w-full sm:ml-auto sm:w-72"
            />
          </div>
          {visibleItems.length > 0 ? (
            <div className="divide-y divide-[var(--border)] overflow-hidden rounded-[var(--radius-sm)]">
              <div className="hidden grid-cols-[3rem_minmax(8rem,1fr)_minmax(10rem,1.5fr)_8rem_7rem_1rem] items-center gap-x-3 border-b border-[var(--border)] px-3 py-3 text-xs font-semibold text-[var(--text-muted)] md:grid">
                <span />
                <span>{t('dashboard.model')}</span>
                <span>{t('dashboard.dataset')}</span>
                <span>{t('dashboard.date')}</span>
                <span>{t('dashboard.result')}</span>
                <span />
              </div>
              {visibleItems.map((r, i) => (
                <RunRow key={i} report={r} onClick={() => openItem(r)} />
              ))}
            </div>
          ) : (
            <div className="py-8 text-center type-body-sm text-[var(--text-muted)]">{t('dashboard.noMatch')}</div>
          )}
          <Pagination
            page={safePage}
            totalPages={filteredItems.length > RECENT_LIMIT ? totalPages : 1}
            onPageChange={setPage}
            className="mt-3"
          />
        </Card>
      ) : scanned ? (
        <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)]">
          <EmptyStateSystem reason="no-data" context={{ view: 'dashboard' }} hint={t('dashboard.noReportsHint')} />
        </div>
      ) : (
        <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)]">
          <EmptyState variant="welcome" icon={<FileText size={28} strokeWidth={1.5} />} title={t('dashboard.welcomeTitle')} hint={t('dashboard.welcomeDesc')} />
        </div>
      )}
    </div>
  )
}
