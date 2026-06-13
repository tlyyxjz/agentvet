# AgentVet

**AI Agent Security Scanner** — detect prompt injection, tool auth bypass, and data leaks before attackers do.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version 0.5.0](https://img.shields.io/badge/version-0.5.0-orange.svg)]()

One command. Find vulnerabilities in your AI agent code.

---

## Features

- **4-Tier Detection Pipeline**
  - **L1** — Regex + AST patterns (fast, broad coverage)
  - **L2** — Ollama semantic filter (removes false positives, ~24s/batch)
  - **L3** — DeepSeek deep audit (attack paths + PoC + CVSS + fix, on HIGH/CRITICAL only)
  - **L4** — Cross-finding attack chain synthesis (how vulns combine into full attack campaigns) — *unique to AgentVet*
- **22 Detection Rules** across 7 categories: prompt injection, tool authorization, data leakage, framework security, secret exposure, MCP config, and supply-chain
- **Web Dashboard** — React + Tailwind UI with scan history and per-finding drilldown
- **CLI Tool** — `agentvet scan ./my-agent --depth 3`
- **Zero data leaves your machine** (L1 is local-only; L2 uses local Ollama; L3 is opt-in via API key)

---

## Quick Start

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com) (optional, for L2 semantic filtering)
  - Pull a model: `ollama pull qwen3:8b`
- DeepSeek API key (optional, for L3 deep audit)

### Install

```bash
git clone https://github.com/tlyyxjz/agentvet.git
cd agentvet

# Using pip
pip install -e .

# Or using uv
uv sync
```

### Usage

**CLI:**

```bash
# L1 only (fastest, some noise)
agentvet scan ./my-agent --depth 1

# L1 + L2 (removes false positives)
agentvet scan ./my-agent --depth 2

# Full pipeline (L1 + L2 + L3 deep audit)
agentvet scan ./my-agent --depth 3

# JSON output
python quick_scan.py --target ./my-agent --depth 3 --json
```

**Web Dashboard:**

```bash
# Start backend
uvicorn web.main:app --host 0.0.0.0 --port 8765

# Start frontend (in another terminal)
cd frontend && npm install && npm run dev
```

Open `http://localhost:5173` to use the web dashboard.

---

## Configuration

Copy `.env.example` to `.env` and set your values:

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama API endpoint |
| `OLLAMA_MODEL` | `qwen3:8b` | Model for L2 filtering |
| `DEEPSEEK_API_KEY` | — | DeepSeek API key for L3 audit |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com/v1/chat/completions` | DeepSeek endpoint |
| `DEEPSEEK_MODEL` | `deepseek-chat` | Model for L3 deep audit |
| `AGENTVET_DB` | `./agentvet.db` | SQLite database path |
| `ALLOWED_ORIGINS` | `http://localhost:5173,http://localhost:3000` | CORS origins |

---

## Architecture

```
scan target
  │
  ├─ L1: RegexRule + ASTRule  (~1s,  free, ~60% coverage)
  │   └─ 17 rules auto-discovered from scanner/rules/
  │
  ├─ L2: Ollama qwen3:8b     (~24s, free, removes ~30% noise)
  │   └─ Batch classify: REAL vs NOISE
  │
  ├─ L3: DeepSeek-chat       (~10s/finding, ~$0.01/scan)
  │   └─ Per-finding: attack path + exploit demo + CVSS + fix
  │
  └─ L4: DeepSeek-chat       (~15s, one call total)
      └─ Cross-finding chain synthesis: how vulns combine into attack campaigns
```

### Detection Rules

| ID | Category | Rule |
|----|----------|------|
| PI-001 | Prompt Injection | Direct user input concatenation to LLM prompt |
| PI-002 | Prompt Injection | Missing input sanitization |
| PI-003 | Prompt Injection | No system defense prompt |
| TA-001 | Tool Auth | High-risk tool without user confirmation |
| TA-002 | Tool Auth | Missing tool permission check |
| DL-001 | Data Leak | Sensitive data logged |
| DL-002 | Data Leak | External service call without audit |
| FW-001 | Frameworks | LangChain @tool executes dangerous op without confirm |
| FW-002 | Frameworks | AutoGen code execution without Docker sandbox |
| FW-003 | Frameworks | CrewAI Task allows code exec without validation |
| FW-004 | Frameworks | Dify plugin API endpoint missing permission check |
| SEC-001 | Secrets | AI provider API key embedded in source code |
| SEC-002 | Secrets | Cloud provider credential in source code |
| SEC-003 | Secrets | Generic password/token/db-url in source code |
| MCP-001 | MCP Config | MCP server registered without authentication |
| MCP-002 | MCP Config | MCP server env contains plaintext secrets |
| MCP-003 | MCP Config | MCP server command from user-writable path |
| MCP-004 | MCP Config | MCP tool description contains prompt injection payload |
| PI-004 | Prompt Injection | IDE rule file (.cursorrules/.windsurfrules) with suspicious directives |
| TA-003 | Tool Auth | Cross-agent delegation loses caller permission context |
| SC-001 | Supply Chain | Skill/plugin contains obfuscated payload or exfiltration endpoint |
| SC-002 | Supply Chain | Skill manifest references suspicious external URL (pastebin/raw/gist) |

All 22 rules auto-discover from `scanner/rules/` — no registration needed. Each rule maps to OWASP LLM Top 10 (2025) and OWASP Agentic AI Top 10 categories.

### Project Structure

```
agentvet/
├── scanner/          # Core scan engine
│   ├── engine.py     # ScanEngine + Rule base classes
│   ├── findings.py   # Finding + ScanReport data models
│   ├── l2_filter.py  # L2 Ollama semantic filter
│   ├── l3_audit.py   # L3 DeepSeek deep audit
│   └── rules/        # Detection rules
├── cli/              # CLI entrypoint
├── web/              # FastAPI backend
├── frontend/         # React + Vite + Tailwind
├── docs/             # Documentation
└── tests/            # Test suite (coming soon)
```

---

## Roadmap

- [ ] npm distribution (`npx agentvet scan`)
- [ ] More detection rules (CSRF, SSRF, path traversal in agent tools)
- [ ] Docker image
- [ ] Supabase migration for cloud deployment
- [ ] VS Code extension
- [ ] GitHub Action (`agentvet/scan`)

---

## License

MIT — see [LICENSE](LICENSE).
