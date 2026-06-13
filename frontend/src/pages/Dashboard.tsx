import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

interface Stats {
  total_scans: number
  avg_duration_ms: number
  clean_scans: number
}

interface ScanItem {
  id: string
  target: string
  score: string
  total_checks: number
  duration_ms: number
  finding_count: number
  created_at: string
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [history, setHistory] = useState<ScanItem[]>([])
  const [scanTarget, setScanTarget] = useState('')
  const [scanDepth, setScanDepth] = useState(3)
  const [scanning, setScanning] = useState(false)

  useEffect(() => {
    fetch('/api/stats')
      .then(r => r.json())
      .then(setStats)
      .catch(() => setStats({ total_scans: 0, avg_duration_ms: 0, clean_scans: 0 }))

    fetch('/api/history?limit=20')
      .then(r => r.json())
      .then(setHistory)
      .catch(() => setHistory([]))
  }, [])

  async function handleScan() {
    if (!scanTarget.trim()) return
    setScanning(true)
    try {
      const res = await fetch(`/scan?target=${encodeURIComponent(scanTarget)}&depth=${scanDepth}`)
      if (res.ok) {
        // Refresh stats + history
        const [newStats, newHistory] = await Promise.all([
          fetch('/api/stats').then(r => r.json()),
          fetch('/api/history?limit=20').then(r => r.json()),
        ])
        setStats(newStats)
        setHistory(newHistory)
        setScanTarget('')
      }
    } finally {
      setScanning(false)
    }
  }

  const scoreColor = (s: string) =>
    s === 'F' || s === 'D' ? 'text-red-400' : s === 'C' ? 'text-yellow-400' : 'text-green-400'

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Dashboard</h2>

      {/* Stats cards */}
      <div className="grid grid-cols-3 gap-6 mb-8">
        <div className="card">
          <div className="text-3xl font-bold text-blue-400">{stats?.total_scans ?? 0}</div>
          <div className="text-sm text-gray-500 mt-1">Total Scans</div>
        </div>
        <div className="card">
          <div className="text-3xl font-bold text-yellow-400">
            {history.filter(s => s.finding_count > 0).length}
          </div>
          <div className="text-sm text-gray-500 mt-1">With Findings</div>
        </div>
        <div className="card">
          <div className="text-3xl font-bold text-green-400">{stats?.clean_scans ?? 0}</div>
          <div className="text-sm text-gray-500 mt-1">Clean (A/A+)</div>
        </div>
      </div>

      {/* Quick scan */}
      <div className="card mb-8">
        <h3 className="text-lg font-semibold mb-3">Quick Scan</h3>
        <div className="flex gap-3 items-center">
          <select
            value={scanDepth}
            onChange={e => setScanDepth(Number(e.target.value))}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-blue-500"
          >
            <option value={1}>L1 — Fast regex+AST</option>
            <option value={2}>L2 — L1 + Semantic (Ollama)</option>
            <option value={3}>L3 — Full Deep Audit (DeepSeek)</option>
          </select>
          <input
            type="text"
            value={scanTarget}
            onChange={e => setScanTarget(e.target.value)}
            placeholder="/path/to/your/agent"
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
            onKeyDown={e => e.key === 'Enter' && handleScan()}
          />
          <button onClick={handleScan} disabled={scanning} className="btn-primary">
            {scanning ? 'Scanning...' : 'Scan'}
          </button>
        </div>
      </div>

      {/* Scan history */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-4">Scan History</h3>
        {history.length === 0 ? (
          <p className="text-gray-500 text-sm">No scans yet. Run your first scan above.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 font-medium">Target</th>
                  <th className="pb-3 font-medium">Score</th>
                  <th className="pb-3 font-medium">Findings</th>
                  <th className="pb-3 font-medium">Duration</th>
                  <th className="pb-3 font-medium">Date</th>
                </tr>
              </thead>
              <tbody>
                {history.map(s => (
                  <tr key={s.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="py-3">
                      <Link to={`/app/scan/${s.id}`} className="text-blue-400 hover:underline">
                        {s.target}
                      </Link>
                    </td>
                    <td className={`py-3 font-mono font-bold ${scoreColor(s.score)}`}>
                      {s.score}
                    </td>
                    <td className="py-3">{s.finding_count}</td>
                    <td className="py-3 text-gray-500">{s.duration_ms.toFixed(0)}ms</td>
                    <td className="py-3 text-gray-500">
                      {new Date(s.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
