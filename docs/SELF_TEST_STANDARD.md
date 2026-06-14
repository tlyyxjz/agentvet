# AgentVet 自测标准（每次改动后强制执行）

**最后更新**: 2026-06-14
**适用范围**: 任何改动——加规则、改引擎、调 prompt、修 bug——都必须通过全部门禁。

---

## 门禁 1：靶场验证（Ground Truth）

**目的**: 确认规则能抓到已知漏洞，不误报安全代码。

### 材料
靶场目录: `tests/fixtures/` 下分两个子目录：

```
tests/fixtures/
├── vulnerable/     # 含已知漏洞的代码（每条规则 >=2 个样本）
│   ├── pi_001_concat.py
│   ├── ta_001_no_confirm.py
│   ├── sec_001_hardcoded_key.py
│   ├── mcp_001_no_auth.json
│   └── ...
├── safe/           # 功能等价但安全的代码（每条规则 >=1 个样本）
│   ├── pi_001_ok.py
│   ├── ta_001_ok.py
│   └── ...
└── manifest.yaml   # 标注文件：每个文件包含哪些漏洞(CWE+行号+规则ID)
```

### 执行

```bash
agentvet scan tests/fixtures/ --depth 1 --json > /tmp/self_test.json
python -m agentvet.tests.validate_fixtures /tmp/self_test.json tests/fixtures/manifest.yaml
```

### 门禁标准

| 指标 | 门禁值 | 说明 |
|------|--------|------|
| **Recall（检出率）** | ≥ 90% | manifest 中标注的漏洞必须检出 90%+ |
| **Precision（精确率）** | ≥ 70% | 报出的结果中 70%+ 必须是真漏洞 |
| **F1 Score** | ≥ 78% | 以上两项的调和平均 |
| **Critical Recall** | = 100% | CRITICAL 级别的漏洞一个不能漏 |

### 验证脚本输出格式

```
TP: 18 | FP: 4 | FN: 2 | TN: 12
Precision: 81.8%  Recall: 90.0%  F1: 85.7%
PASS: F1 85.7% >= 78%
FAIL: Critical Recall 87.5% < 100%  ← 门禁失败，不准发布
  Missing: SEC-001 in secrets_leaked.py:0 (manifest says line 5)
```

---

## 门禁 2：稳定性（扫 5 次看方差）

**目的**: L2/L3/L4 都依赖 LLM，必须测多头运行的输出一致性。

### 执行

```bash
python -m agentvet.tests.stability_test --target tests/fixtures/vulnerable/ --runs 5 --depth 3
```

### 门禁标准

| 指标 | 门禁值 |
|------|--------|
| 每次扫描的 finding 数量方差 | ≤ 10%（L1 必须为 0%，完全确定性） |
| 高严重度（CRITICAL+HIGH）的 Jaccard 相似度 | ≥ 0.85 |
| L2 对同一条 finding 的 keep/drop 判决一致性 | ≥ 90% |

---

## 门禁 3：性能

**目的**: 不能越改越慢，大项目不能崩。

### 执行

```bash
# 小目标：100 个文件以内的性能基线
python -m agentvet.tests.perf_test --target tests/fixtures/ --depth 1

# 大目标：1000+ 文件不崩不过度消耗
python -m agentvet.tests.perf_test --target ~/.codex/ --depth 1
```

### 门禁标准

| 场景 | 指标 | 门禁值 |
|------|------|--------|
| 小目标 depth=1 | 扫描耗时 | ≤ 3s |
| 小目标 depth=3 | 扫描耗时 | ≤ 120s（受 API 速度影响，超时算 fail） |
| 大目标 depth=1 | 扫描耗时 | ≤ 60s |
| 大目标 | 内存占用 | ≤ 500MB |
| 大目标 | 崩/异常退出 | 不允许 |

---

## 门禁 4：分层有效性

**目的**: 每一层都必须比上一层带来增量价值，不是空转。

### 执行

```bash
python -m agentvet.tests.layer_test --target tests/fixtures/ --all-depths
```

### 门禁标准

| 对比 | 指标 | 门禁值 |
|------|------|--------|
| L1 vs L1+L2 | FP 减少率 | ≥ 30%（L2 必须过滤掉 30%+ 的误报） |
| L1+L2 vs L1+L2+L3 | 新发现 HIGH/CRITICAL | ≥ 1 条（L3 必须贡献增量） |
| L3 vs L4 | 有效攻击链 | 当 ≥2 HIGH/CRITICAL 时，L4 必须产出 ≥1 条 chain，且 chain.stages 非空 |

---

## 门禁 5：CLI 兼容性

**目的**: 命令行接口不碎，返回值正确。

### 执行

```bash
# 帮助信息正常
agentvet --help | grep -q "usage:" && echo "PASS" || echo "FAIL"

# --json 输出是合法 JSON
agentvet scan tests/fixtures/ --depth 1 --json 2>/dev/null | python -c "import sys,json; json.load(sys.stdin); print('PASS')"

# --fail-on CRITICAL 对含 CRITICAL 的目标返回非 0
agentvet scan tests/fixtures/vulnerable/ --depth 1 --fail-on CRITICAL --json >/dev/null 2>&1
if [ $? -ne 0 ]; then echo "PASS: exit code non-zero on CRITICAL"; else echo "FAIL: should exit non-zero"; fi

# --fail-on CRITICAL 对安全代码返回 0
agentvet scan tests/fixtures/safe/ --depth 1 --fail-on CRITICAL --json >/dev/null 2>&1
if [ $? -eq 0 ]; then echo "PASS: exit code 0 on clean target"; else echo "FAIL: false positive exit"; fi
```

### 门禁标准

全部 PASS，一项 FAIL 即不通过。

---

## 门禁 6：导入 + Lint

**目的**: 包能用、代码干净。

### 执行

```bash
# 导入不报错
python -c "from scanner.engine import ScanEngine; from scanner.findings import Finding, Severity, ScanReport; print('OK')"

# 所有规则可实例化
python -c "from scanner.engine import ScanEngine; e=ScanEngine(); print(f'{len(e.rules)} rules loaded')"

# ruff 检查
ruff check scanner/ cli/ web/ --select E,F,W 2>&1
```

### 门禁标准

- 导入成功
- 规则数 ≥ 22
- ruff 零错误（E/F/W 级别）

---

## 门禁 7：规则文件自检

**目的**: 每条规则的文件头信息完整。

### 执行

```bash
python -m agentvet.tests.rule_audit
```

### 门禁标准

每条规则必须满足：

- `rule_id` 格式: `<CATEGORY>-<NNN>`（如 `PI-001`）
- `title` 非空
- `description`  ≥ 30 字符
- `file_patterns` 非空列表
- `owasp_ids` 非空列表
- `fix_suggestion()` 返回值非空
- `_severity()` 返回有效的 Severity 枚举值

---

## 门禁 8：数据模型完整性

**目的**: Finding/ScanReport 的所有字段正确传递，L2/L3/L4 附加字段不丢。

### 执行

```bash
python -m agentvet.tests.model_test
```

### 门禁标准

- Finding 的 10 个字段全部有值（不依赖默认值蒙混）
- ScanReport 的 `l2_verdicts`, `l3_model`, `chain` 字段在全 depth 扫描后非空
- JSON 序列化/反序列化 round-trip 不丢字段

---

## 快速门禁（日常小改动用）

如果改动范围是**单条规则、单行 bug fix、文档**，可以只跑快速门禁（< 30 秒）：

```bash
python -c "from scanner.engine import ScanEngine; print('OK')" \
  && ruff check scanner/ cli/ --select E,F,W 2>&1 \
  && agentvet scan tests/fixtures/ --depth 1 --fail-on CRITICAL --json >/dev/null 2>&1
```

三项全过 = PASS。快速门禁通过可以 commit，但**不能发布 PyPI**。PyPI 发布必须跑完全部门禁。

---

## 发布前全部门禁（PyPI / GitHub Release）

```bash
python -m agentvet.tests.self_test --full
```

该命令按顺序执行门禁 1-8，任一失败立即停止并报告。全过程预计 3-8 分钟（含 API 调用）。

---

## 门禁失败处理流程

```
门禁失败
  ├─ 靶场验证失败 → 不许发版，修规则或更新 manifest
  ├─ 稳定性失败 → 检查 L2/L3/L4 prompt 变更，回退重试
  ├─ 性能失败 → git bisect 找到退化点，修
  ├─ 分层失败 → 检查对应层是否被意外禁用/API key 失效
  └─ CLI/Lint 失败 → 修完重跑，不允许带着 lint 错误发版
```

**铁律**: 门禁失败 = 不发版。不存在"门禁失败但我觉得没关系"的特例。
