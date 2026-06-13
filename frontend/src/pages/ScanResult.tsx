import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'

interface Finding {
  rule_id: string
  title: string
  severity: string
  file_path: string
  line_number: number
  description: string
  code_snippet: string
  attack_demo: string
  fix_suggestion: string
}

interface Tiers {
  l1_findings: number
  l2_dropped: number
  l2_model: string
  l2_duration_ms: number
  l3_audited: number
  l3_model: string
  l3_duration_ms: number
}

interface Report {
  id: string
  target: string
  score: string
  total_checks: number
  duration_ms: number
  created_at: string
  summary: Record<string, number>
  findings: Finding[]
  tiers: Tiers
}

export default function ScanResult() {
  const { id } = useParams<{ id: string }>()
  const [report, setReport] = useState<Report | null>(null)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  useEffect(() => {
    fetch(`/api/report/${id}`)
      .then(r => r.json())
      .then(setReport)
      .catch(console.error)
  }, [id])

  if (!report) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-gray-500">Loading report...</p>
      </div>
    )
  }

  const toggleExpand = (idx: number) => {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx)
      else next.add(idx)
      return next
    })
  }

  const sevBadge = (sev: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-600/20 text-red-400 border-red-600/30',
      high: 'bg-red-600/20 text-red-400 border-red-600/30',
      medium: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/30',
      low: 'bg-green-600/20 text-green-400 border-green-600/30',
      info: 'bg-gray-600/20 text-gray-400 border-gray-600/30',
    }
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-medium border ${colors[sev] || colors.info}`}>
        {sev.toUpperCase()}
      </span>
    )
  }

  const scoreColor = (s: string) =>
    s === 'F' || s === 'D' ? 'text-red-400' : s === 'C' ? 'text-yellow-400' : 'text-green-400'

  return (
    <div className="max-w-4xl">
      <Link to="/app" className="text-gray-500 hover:text-gray-300 text-sm mb-4 inline-block">
        &larr; Back to Dashboard
      </Link>

      {/* Header */}
      <div className="card mb-6">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-xl font-bold mb-1">{report.target}</h2>
            <p className="text-sm text-gray-500">
              {new Date(report.created_at).toLocaleString()} &middot;{' '}
              {report.total_checks} checks &middot; {report.duration_ms.toFixed(0)}ms
            </p>
          </div>
          <div className={`text-4xl font-bold ${scoreColor(report.score)}`}>
            {report.score}
          </div>
        </div>

        {/* Summary pills */}
        <div className="flex gap-4 mt-4">
          {report.summary.critical > 0 && (
            <span className="px-3 py-1 bg-red-600/20 text-red-400 rounded-full text-sm font-medium">
              {report.summary.critical} Critical
            </span>
          )}
          {report.summary.high > 0 && (
            <span className="px-3 py-1 bg-red-600/20 text-red-400 rounded-full text-sm font-medium">
              {report.summary.high} High
            </span>
          )}
          {report.summary.medium > 0 && (
            <span className="px-3 py-1 bg-yellow-600/20 text-yellow-400 rounded-full text-sm font-medium">
              {report.summary.medium} Medium
            </span>
          )}
          {report.summary.low > 0 && (
            <span className="px-3 py-1 bg-green-600/20 text-green-400 rounded-full text-sm font-medium">
              {report.summary.low} Low
            </span>
          )}
        </div>

        {/* Tier pipeline */}
        {report.tiers && (
          <div className="mt-4 pt-4 border-t border-gray-800 flex items-center gap-3 text-xs">
            <div className="flex items-center gap-1.5">
              <span className="px-2 py-0.5 bg-gray-700 rounded text-gray-300">L1</span>
              <span className="text-gray-500">{report.tiers.l1_findings} found</span>
            </div>
            <span className="text-gray-600">&rarr;</span>
            <div className="flex items-center gap-1.5">
              <span className="px-2 py-0.5 bg-blue-900/40 rounded text-blue-300">L2</span>
              <span className="text-gray-500">
                {report.tiers.l2_dropped > 0
                  ? `-${report.tiers.l2_dropped} noise · ${report.tiers.l2_model}`
                  : 'skipped'}
              </span>
            </div>
            <span className="text-gray-600">&rarr;</span>
            <div className="flex items-center gap-1.5">
              <span className="px-2 py-0.5 bg-purple-900/40 rounded text-purple-300">L3</span>
              <span className="text-gray-500">
                {report.tiers.l3_audited > 0
                  ? `${report.tiers.l3_audited} audited · ${report.tiers.l3_model}`
                  : 'skipped'}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Findings */}
      <div className="space-y-4">
        {report.findings.map((f, idx) => (
          <div key={idx} className="card">
            <div
              className="flex items-start gap-3 cursor-pointer"
              onClick={() => toggleExpand(idx)}
            >
              {sevBadge(f.severity)}
              <div className="flex-1">
                <h3 className="font-semibold">{f.title}</h3>
                <p className="text-sm text-gray-500 mt-0.5">
                  {f.file_path}:{f.line_number}
                </p>
              </div>
              <span className="text-gray-600 text-sm">
                {expanded.has(idx) ? 'Collapse' : 'Expand'}
              </span>
            </div>

            {expanded.has(idx) && (
              <div className="mt-4 pt-4 border-t border-gray-800 space-y-4">
                <p className="text-gray-300 text-sm">{f.description}</p>

                {f.code_snippet && (
                  <div>
                    <div className="text-xs text-gray-500 mb-1">Code</div>
                    <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs text-gray-300 overflow-x-auto">
                      {f.code_snippet}
                    </pre>
                  </div>
                )}

                {f.attack_demo && (
                  <div>
                    <div className="text-xs text-red-400 mb-1">Attack Demo</div>
                    <pre className="bg-red-950/30 border border-red-900/30 rounded-lg p-3 text-xs text-red-300 overflow-x-auto">
                      {f.attack_demo}
                    </pre>
                  </div>
                )}

                {f.fix_suggestion && (
                  <div>
                    <div className="text-xs text-green-400 mb-1">Fix</div>
                    <pre className="bg-green-950/20 border border-green-900/30 rounded-lg p-3 text-xs text-green-300 overflow-x-auto whitespace-pre-wrap">
                      {f.fix_suggestion}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {report.findings.length === 0 && (
        <div className="card text-center py-12">
          <p className="text-2xl font-bold text-green-400 mb-2">No vulnerabilities found</p>
          <p className="text-gray-500">Your agent passed all {report.total_checks} checks.</p>
        </div>
      )}
    </div>
  )
}
