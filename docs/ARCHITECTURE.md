# AgentVet Architecture

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| CLI | Python 3.10+ | Zero deps, cross-platform |
| Scan Engine | Python AST + Regex | Free, fast (~1s), no GPU needed |
| L2 Filter | Ollama (qwen3:8b) | Local, free, semantic noise filtering |
| L3 Audit | DeepSeek-chat API | Deep attack-path analysis on confirmed findings |
| Web Backend | FastAPI | Async, auto OpenAPI docs, lightweight |
| Database | SQLite | Single-file, zero config |
| Frontend | React 18 + Vite + Tailwind | MIT license, fast dev |

## 3-Tier Detection Pipeline

All three tiers are **implemented and operational**.

| Tier | Technology | Cost | When | Coverage |
|------|-----------|------|------|----------|
| L1 | Regex + AST rules | $0 | Always | Broad pattern matching |
| L2 | Ollama semantic filter | $0 (local) | `depth >= 2` | Removes ~30% false positives |
| L3 | DeepSeek deep audit | ~$0.01/scan | `depth >= 3` | Attack path analysis on HIGH/CRITICAL |

### Pipeline Flow

```
L1: 20 findings (noisy)
  → L2: 4 findings (noise removed)
    → L3: 4 audited (attack path + PoC + CVSS + fix)
```

Depth control: `--depth 1` = L1 only, `--depth 2` = L1+L2, `--depth 3` = full pipeline.

## Project Structure

```
agentvet/
├── scanner/              # Core scan engine
│   ├── __init__.py
│   ├── engine.py         # ScanEngine + Rule/RegexRule/ASTRule base classes
│   ├── findings.py       # Finding + ScanReport data models
│   ├── l2_filter.py      # L2 Ollama semantic filter (batch classify)
│   ├── l3_audit.py       # L3 DeepSeek deep audit (per-finding)
│   └── rules/
│       ├── prompt_injection.py   # PI-001/002/003
│       ├── tool_auth.py          # TA-001/002
│       └── data_leak.py          # DL-001/002
├── cli/                  # CLI tool
│   └── main.py           # `agentvet scan ./dir --depth 3`
├── quick_scan.py         # Standalone scan script (legacy convenience)
├── web/                  # FastAPI backend
│   └── main.py           # /scan, /api/history, /api/report/:id, /api/stats
├── frontend/             # React + Vite + Tailwind
│   └── src/
│       ├── components/   # Layout, ErrorBoundary
│       └── pages/        # Landing, Dashboard, ScanResult
├── docs/
│   └── ARCHITECTURE.md
├── .env.example          # Environment variable reference
├── pyproject.toml        # Python project config
└── README.md
```

## Frontend Routes

```
/              → Landing page
/app           → Dashboard (stats + quick scan + history)
/app/scan/:id  → Scan result detail (expandable findings)
```

## API Endpoints

```
POST /scan?target=/path&depth=3    → Scan with tier depth control
POST /api/upload-scan              → Upload single file and scan
GET  /api/history?limit=20&offset  → Paginated scan history
GET  /api/report/:id               → Full report with tier metadata
GET  /api/stats                    → Aggregate statistics
```

## Detection Rules

Each rule is a Python class inheriting from `RegexRule`:

| ID | Category | Rule |
|----|----------|------|
| PI-001 | Prompt Injection | Direct user input concatenation |
| PI-002 | Prompt Injection | Missing input sanitization |
| PI-003 | Prompt Injection | No system defense prompt |
| TA-001 | Tool Auth | High-risk tool without confirmation |
| TA-002 | Tool Auth | Missing tool permission check |
| DL-001 | Data Leak | Sensitive data in logs |
| DL-002 | Data Leak | External service without audit |

Add a new rule: create a file in `scanner/rules/`, subclass `RegexRule`, and register in `engine.py`'s `_default_rules()`.

## Configuration

See `.env.example` for all environment variables:

- `OLLAMA_BASE_URL` — Ollama host (default: `http://127.0.0.1:11434`)
- `OLLAMA_MODEL` — L2 model (default: `qwen3:8b`)
- `DEEPSEEK_API_KEY` — Required for L3 deep audit
- `DEEPSEEK_BASE_URL` — DeepSeek API endpoint
- `DEEPSEEK_MODEL` — L3 model (default: `deepseek-chat`)
- `ALLOWED_ORIGINS` — CORS origins (comma-separated)
- `AGENTVET_DB` — SQLite database path

## Deployment

```bash
# Backend
uvicorn web.main:app --host 0.0.0.0 --port 8765

# Frontend (dev)
cd frontend && npm run dev

# Frontend (production build)
cd frontend && npm run build
```
