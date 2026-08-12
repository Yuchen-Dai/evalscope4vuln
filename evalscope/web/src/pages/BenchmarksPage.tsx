import { useEffect, useMemo, useRef, useState, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { useLocale } from '@/contexts/LocaleContext'
import { listBenchmarks } from '@/api/eval'
import type { BenchmarkEntry } from '@/api/types'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import MarkdownRenderer from '@/components/common/MarkdownRenderer'
import SearchInput from '@/components/ui/SearchInput'
import Badge from '@/components/ui/Badge'
import Pagination from '@/components/ui/Pagination'
import { BookOpen, X, Database, Layers, Tag } from 'lucide-react'

// 漏洞挖掘测评平台：benchmark 目录只承载漏洞 benchmark（后端 /eval/benchmarks 已只返 vuln_*）。
// 移除上游通用 LLM 评测的类目 Tab（text/vlm/agent/aigc）、VLM/Agent/AIGC 徽标、few-shot、paper。
const PAGE_SIZE = 24

function stripMarkdown(md: string): string {
  return md
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/\*(.+?)\*/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/^[-*]\s+/gm, '')
    .replace(/^\d+\.\s+/gm, '')
    .trim()
}

export default function BenchmarksPage() {
  const { t, locale } = useLocale()
  const [loading, setLoading] = useState(true)
  const [allBenchmarks, setAllBenchmarks] = useState<BenchmarkEntry[]>([])
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [selectedTags, setSelectedTags] = useState<string[]>([])
  const [selectedEntry, setSelectedEntry] = useState<BenchmarkEntry | null>(null)
  const [page, setPage] = useState(1)
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined)

  const normalize = (e: BenchmarkEntry): BenchmarkEntry => ({
    ...e,
    pretty_name: e.pretty_name ?? e.meta?.pretty_name ?? e.name,
    tags: Array.isArray(e.tags) ? e.tags : Array.isArray((e.meta as Record<string, unknown>)?.tags) ? (e.meta as Record<string, unknown>).tags as string[] : [],
    subset_list: Array.isArray(e.subset_list) ? e.subset_list : Array.isArray((e.meta as Record<string, unknown>)?.subset_list) ? (e.meta as Record<string, unknown>).subset_list as string[] : [],
    total_samples: e.total_samples ?? (e.meta as Record<string, unknown>)?.total_samples as number ?? 0,
    dataset_id: e.dataset_id ?? (e.meta as Record<string, unknown>)?.dataset_id as string ?? '',
  })

  useEffect(() => {
    const controller = new AbortController()
    const load = async () => {
      setLoading(true)
      try {
        const res = await listBenchmarks(undefined, true, controller.signal)
        if (controller.signal.aborted) return
        // 后端只返回 vuln_* benchmark（text 桶）；忽略通用 multimodal/agent/aigc
        const list = (res.text ?? []).map((e) => normalize(e))
        setAllBenchmarks(list)
      } catch {
        /* ignore */
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }
    load()
    return () => controller.abort()
  }, [])

  useEffect(() => {
    timerRef.current = setTimeout(() => setDebouncedSearch(search), 300)
    return () => clearTimeout(timerRef.current)
  }, [search])

  const allTags = useMemo(() => {
    const tagSet = new Set<string>()
    for (const b of allBenchmarks) {
      for (const tag of b.tags ?? []) tagSet.add(tag)
    }
    return Array.from(tagSet).sort()
  }, [allBenchmarks])

  const getDescription = useCallback(
    (entry: BenchmarkEntry) => {
      const desc = locale === 'zh' ? entry.description?.zh : entry.description?.en
      const full = desc?.full
      if (!full) return t('benchmarks.noDescription')
      return stripMarkdown(full)
    },
    [locale, t],
  )

  const items = useMemo(() => {
    let result = allBenchmarks
    if (selectedTags.length > 0) {
      result = result.filter((e) => selectedTags.some((tag) => (e.tags ?? []).includes(tag)))
    }
    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase()
      result = result.filter(
        (e) =>
          e.name.toLowerCase().includes(q) ||
          (e.pretty_name ?? '').toLowerCase().includes(q) ||
          getDescription(e).toLowerCase().includes(q) ||
          (e.tags ?? []).some((tag) => tag.toLowerCase().includes(q)),
      )
    }
    return result
  }, [allBenchmarks, debouncedSearch, selectedTags, getDescription])

  const totalPages = Math.max(1, Math.ceil(items.length / PAGE_SIZE))
  const safePage = Math.min(page, totalPages)
  const pagedItems = items.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE)

  const handleCardClick = useCallback((entry: BenchmarkEntry) => {
    setSelectedEntry(entry)
  }, [])

  const closeDetail = useCallback(() => setSelectedEntry(null), [])

  const toggleTag = (tag: string) => {
    setPage(1)
    setSelectedTags((prev) => (prev.includes(tag) ? prev.filter((x) => x !== tag) : [...prev, tag]))
  }

  const clearFilters = () => {
    setPage(1)
    setSelectedTags([])
    setSearch('')
  }

  const hasActiveFilters = selectedTags.length > 0 || debouncedSearch.length > 0

  if (loading) return <LoadingSpinner />

  return (
    <div className="page-enter space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">{t('benchmarks.title')}</h1>
        <span className="text-sm text-[var(--text-muted)]">
          {t('benchmarks.showing', { n: items.length, total: allBenchmarks.length })}
        </span>
      </div>

      {/* Controls */}
      <div className="flex flex-col gap-3">
        <SearchInput
          value={search}
          onChange={(v) => { setSearch(v); setPage(1) }}
          placeholder={t('benchmarks.search')}
          className="w-full sm:w-72"
        />
        {allTags.length > 0 && (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
              <Tag size={12} />
              <span>{t('benchmarks.filterByTag')}</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {allTags.map((tag) => (
                <button
                  key={tag}
                  onClick={() => toggleTag(tag)}
                  className={['px-2.5 py-1 rounded-full text-xs font-medium transition-all duration-[var(--transition)] cursor-pointer border',
                    selectedTags.includes(tag)
                      ? 'bg-[var(--accent)] text-[var(--text-on-filled)] border-[var(--accent)] shadow-[var(--shadow-glow-soft)]'
                      : 'bg-[var(--bg-card)] text-[var(--text-muted)] border-[var(--border)] hover:border-[var(--accent-dim)] hover:text-[var(--accent)]',
                  ].join(' ')}
                >
                  {tag}
                </button>
              ))}
            </div>
          </div>
        )}
        {hasActiveFilters && (
          <div className="flex items-center gap-2">
            {selectedTags.map((tag) => (
              <span key={tag} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-[var(--accent-dim)] text-[var(--accent)]">
                {tag}
                <button onClick={() => toggleTag(tag)} className="cursor-pointer hover:text-white"><X size={10} /></button>
              </span>
            ))}
            {debouncedSearch && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-[var(--accent-dim)] text-[var(--accent)]">
                "{debouncedSearch}"
                <button onClick={() => setSearch('')} className="cursor-pointer hover:text-white"><X size={10} /></button>
              </span>
            )}
            <button onClick={clearFilters} className="px-3 py-1.5 text-xs font-medium rounded-[var(--radius-sm)] text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--bg-card2)] transition-colors cursor-pointer">
              {t('benchmarks.clearFilters')}
            </button>
          </div>
        )}
      </div>

      {/* Cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {pagedItems.map((entry) => (
          <div key={entry.name} onClick={() => handleCardClick(entry)}
            className="card-hover rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-card)] p-5 flex flex-col cursor-pointer">
            <div className="flex items-start gap-3 flex-1">
              <div className="mt-0.5 shrink-0 w-8 h-8 rounded-[var(--radius-sm)] bg-[var(--accent-dim)] flex items-center justify-center">
                <BookOpen size={16} className="text-[var(--accent)]" />
              </div>
              <div className="min-w-0 flex-1">
                <h3 className="text-sm font-semibold text-[var(--text)] truncate">{entry.pretty_name}</h3>
                <p className="text-[11px] text-[var(--text-muted)] font-mono mt-0.5">{entry.name}</p>
              </div>
            </div>
            <p className="text-xs text-[var(--text-muted)] mt-3 line-clamp-2 leading-relaxed">{getDescription(entry)}</p>
            <div className="flex items-center gap-3 mt-3 text-[11px] text-[var(--text-muted)]">
              {entry.total_samples > 0 && (
                <span className="inline-flex items-center gap-1"><Database size={10} />{entry.total_samples.toLocaleString()}</span>
              )}
              {(entry.subset_list ?? []).length > 0 && (
                <span className="inline-flex items-center gap-1"><Layers size={10} />{(entry.subset_list ?? []).length} {t('benchmarks.subsets')}</span>
              )}
            </div>
            <div className="flex flex-wrap gap-1 mt-2.5">
              {(entry.tags ?? []).map((tag) => (
                <Badge key={tag} variant="default" className="text-[9px]">{tag}</Badge>
              ))}
              {(entry.metrics ?? []).map((m) => (
                <Badge key={m} variant="success" className="text-[9px]">{m}</Badge>
              ))}
            </div>
          </div>
        ))}
      </div>

      <Pagination page={safePage} totalPages={totalPages} onPageChange={setPage} />

      {/* Detail modal */}
      {selectedEntry != null && createPortal(
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }} onClick={closeDetail}>
          <div className="relative w-full max-w-3xl max-h-[85vh] rounded-[var(--radius-lg)] bg-[var(--bg-card)] border border-[var(--border)] shadow-2xl flex flex-col overflow-hidden"
            onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start gap-3 p-5 pb-3 border-b border-[var(--border)]">
              <div className="shrink-0 w-10 h-10 rounded-[var(--radius-sm)] bg-[var(--accent-dim)] flex items-center justify-center">
                <BookOpen size={20} className="text-[var(--accent)]" />
              </div>
              <div className="min-w-0 flex-1">
                <h2 className="text-lg font-semibold text-[var(--text)]">{selectedEntry.pretty_name}</h2>
                <p className="text-xs text-[var(--text-muted)] font-mono mt-0.5">{selectedEntry.name}</p>
                <div className="flex items-center gap-3 mt-2 text-xs text-[var(--text-muted)]">
                  {selectedEntry.total_samples > 0 && (
                    <span className="inline-flex items-center gap-1"><Database size={11} />{selectedEntry.total_samples.toLocaleString()} {t('benchmarks.samples')}</span>
                  )}
                  {(selectedEntry.subset_list ?? []).length > 0 && (
                    <span className="inline-flex items-center gap-1"><Layers size={11} />{(selectedEntry.subset_list ?? []).length} {t('benchmarks.subsets')}</span>
                  )}
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {(selectedEntry.tags ?? []).map((tag) => (
                    <Badge key={tag} variant="default" className="text-[10px]">{tag}</Badge>
                  ))}
                  {(selectedEntry.metrics ?? []).map((m) => (
                    <Badge key={m} variant="success" className="text-[10px]">{m}</Badge>
                  ))}
                </div>
              </div>
              <button onClick={closeDetail} className="shrink-0 p-1.5 rounded-[var(--radius-sm)] text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--bg-card2)] transition-colors cursor-pointer">
                <X size={18} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              <MarkdownRenderer content={(locale === 'zh' ? selectedEntry.description?.zh?.full : selectedEntry.description?.en?.full) ?? ''} />
            </div>
          </div>
        </div>, document.body)}

      {items.length === 0 && !loading && (
        <div className="text-center py-16">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-[var(--bg-deep)] mb-4">
            <BookOpen size={24} className="text-[var(--text-dim)]" />
          </div>
          <p className="text-sm text-[var(--text-muted)]">{t('benchmarks.noResults')}</p>
          {hasActiveFilters && (
            <button onClick={clearFilters} className="mt-4 px-3 py-1.5 text-xs font-medium rounded-[var(--radius-sm)] border border-[var(--border-md)] text-[var(--text)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors cursor-pointer">
              {t('benchmarks.clearFilters')}
            </button>
          )}
        </div>
      )}
    </div>
  )
}
