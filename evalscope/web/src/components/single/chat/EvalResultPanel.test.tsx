import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { LocaleProvider } from '@/contexts/LocaleContext'
import { ThemeProvider } from '@/contexts/ThemeContext'
import { EvalResultPanel } from './EvalResultPanel'

afterEach(cleanup)

function renderPanel(nScore: number) {
  return render(
    <ThemeProvider>
      <LocaleProvider>
        <EvalResultPanel
          pred="B"
          gold="B"
          nScore={nScore}
          score={{ acc: nScore }}
          metadata={{ id: '1' }}
          threshold={0.99}
          showPred
        />
      </LocaleProvider>
    </ThemeProvider>,
  )
}

describe('EvalResultPanel', () => {
  it('uses one neutral label hierarchy and a restrained success score', () => {
    renderPanel(1)

    // evalResult (panel header) and extractedAnswer both render the "Finding"
    // term per the vuln repositioning, so the label appears more than once.
    const findingLabels = screen.getAllByText('Finding')
    expect(findingLabels.length).toBeGreaterThanOrEqual(1)
    expect(findingLabels[0]).toHaveClass('type-label-xs')
    expect(screen.getByText('Ground Truth (vulnerability)')).toHaveClass('type-label-xs')
    expect(screen.getByText('100.0%')).toHaveStyle({ color: 'var(--success)' })
  })

  it('keeps verbose details collapsed and uses danger styling below the filter', () => {
    renderPanel(0.2)

    expect(screen.getByRole('button', { name: 'Score Detail' })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('"acc"')).not.toBeInTheDocument()
    expect(screen.getByText('20.0%')).toHaveStyle({ color: 'var(--danger)' })
  })
})
