import { useEffect, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'

interface Props {
  open: boolean
  onClose: () => void
  title: ReactNode
  children: ReactNode
  footer?: ReactNode
  /** max-width 类（tailwind），默认 max-w-lg */
  maxWidth?: string
}

/**
 * 通用模态框：createPortal 到 body，背景点击/Esc 关闭，header + 可滚动 body + 可选 footer。
 * 样式抽自 BenchmarksPage 的 detail modal（fixed inset-0 + backdrop blur）。
 */
export default function Modal({ open, onClose, title, children, footer, maxWidth = 'max-w-lg' }: Props) {
  // Esc 关闭
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return createPortal(
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
      onClick={onClose}
    >
      <div
        className={`relative w-full ${maxWidth} max-h-[85vh] rounded-[var(--radius-lg)] bg-[var(--bg-card)] border border-[var(--border)] shadow-2xl flex flex-col overflow-hidden`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-3 p-5 pb-3 border-b border-[var(--border)]">
          <h2 className="text-lg font-semibold text-[var(--text)]">{title}</h2>
          <button
            onClick={onClose}
            className="shrink-0 p-1.5 rounded-[var(--radius-sm)] text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--bg-card2)] transition-colors cursor-pointer"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
        {footer && <div className="p-4 border-t border-[var(--border)] flex justify-end gap-2">{footer}</div>}
      </div>
    </div>,
    document.body,
  )
}
