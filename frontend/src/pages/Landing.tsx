import { Link } from 'react-router-dom'

export default function Landing() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Nav */}
      <nav className="flex items-center justify-between px-8 py-4 border-b border-gray-800">
        <span className="text-xl font-bold gradient-text">AgentVet</span>
        <div className="flex gap-4 items-center">
          <a href="https://github.com/agentvet/agentvet" className="text-gray-400 hover:text-gray-200 text-sm">
            GitHub
          </a>
          <Link to="/app" className="btn-primary text-sm">
            Open App
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section className="max-w-3xl mx-auto px-8 pt-24 pb-16 text-center">
        <h1 className="text-5xl font-bold mb-6 leading-tight">
          Your AI Agent's{' '}
          <span className="gradient-text">Security Checkup</span>
        </h1>
        <p className="text-xl text-gray-400 mb-4">
          One command. 3 seconds. Find prompt injection, tool auth bypass, and data leaks
          before attackers do.
        </p>

        {/* Terminal preview */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-left font-mono text-sm mb-8">
          <div className="flex gap-2 mb-4">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <div className="w-3 h-3 rounded-full bg-green-500" />
          </div>
          <span className="text-green-400">$</span>{' '}
          <span className="text-white">agentvet scan ./my-agent</span>
          {'\n\n'}
          <span className="text-blue-400">AgentVet v0.1.0</span> — AI Agent Security Scanner
          {'\n'}
          {'\n'}
          <span className="text-red-400">[!] HIGH — Prompt Injection</span>{' '}
          <span className="text-gray-500">agent.py:87</span>
          {'\n'}
          <span className="text-red-400">[!] HIGH — Tool Auth Bypass</span>{' '}
          <span className="text-gray-500">handler.py:143</span>
          {'\n'}
          <span className="text-yellow-400">[~] MEDIUM — Data Leak via Log</span>{' '}
          <span className="text-gray-500">handler.py:203</span>
          {'\n'}
          {'\n'}
          Score: <span className="text-red-400 font-bold">D</span> (2 high, 1 medium){' '}
          <span className="text-gray-500">| 2.3s | 47 checks</span>
          {'\n'}
          <span className="text-gray-500">Full report: ./agentvet-report.json</span>
        </div>

        <div className="flex gap-4 justify-center">
          <Link to="/app" className="btn-primary text-lg px-8 py-3">
            Start Free Scan
          </Link>
          <a
            href="https://github.com/agentvet/agentvet"
            className="btn-ghost text-lg px-8 py-3"
          >
            View on GitHub
          </a>
        </div>

        <div className="flex gap-8 justify-center mt-8 text-sm text-gray-500">
          <span>No data leaves your machine</span>
          <span>Open source (MIT)</span>
          <span>10 free scans/month</span>
        </div>
      </section>

      {/* Features */}
      <section className="max-w-4xl mx-auto px-8 py-16 grid grid-cols-3 gap-8">
        <FeatureCard
          title="Prompt Injection"
          desc="Detect unsanitized user input reaching LLM prompts. Stop 'ignore all previous instructions' attacks."
        />
        <FeatureCard
          title="Tool Authorization"
          desc="Find high-risk tools (shell, file delete, network) registered without user confirmation."
        />
        <FeatureCard
          title="Data Leakage"
          desc="Catch sensitive data in logs, unredacted LLM I/O, and unauthorized external service calls."
        />
      </section>

      {/* Footer */}
      <footer className="text-center py-8 text-gray-600 text-sm border-t border-gray-800">
        AgentVet — Built for the AI agent era. Scan your agents before attackers do.
      </footer>
    </div>
  )
}

function FeatureCard({ title, desc }: { title: string; desc: string }) {
  return (
    <div className="card">
      <h3 className="text-lg font-semibold mb-2">{title}</h3>
      <p className="text-gray-400 text-sm leading-relaxed">{desc}</p>
    </div>
  )
}
