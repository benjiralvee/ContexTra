# ContexTra: Automated Context-Aware Triaging of Cryptographic API Misuse Alarms

This repository contains the code, data, and result artifacts for the CCS 2026 paper.

## Overview

ContexTra is an agentic system that refines cryptographic API misuse alerts produced by upstream static analysis tools (Bandit, Semgrep, Dlint, CodeQL, CryptoGuard). Given an alert, it iteratively investigates the repository using code analysis tools, reading files, searching code, traversing call graphs, running static analyzers, then classifies the alert as:

- **TP** (True Positive): genuine cryptographic misuse requiring a fix
- **FP** (False Positive): the alert is incorrect or benign
- **NON_ACTIONABLE**: a real weakness whose fix is precluded by a protocol/specification mandate

## Repository Structure

```
ContexTra-artifact/
├── README.md                  ← this file
├── run.sh                     ← single entry point (one target per RQ)
├── requirements.txt           ← Python dependencies
│
├── contextra/                 ← main ContexTra agent (9 tools, supports ablation configs)
│   ├── main.py                   entry point
│   ├── classifier.py             agentic investigation loop (15-iteration cap)
│   ├── config.py                 all configuration (env-driven, no hardcoded paths)
│   ├── llm_interface.py          generic LLM client (Claude / OpenAI / Ollama)
│   ├── prompts.py                prompt construction
│   ├── tools.py                  9 investigation tools
│   ├── fp_identifier_prompt.md   the prompt template
│   └── .env.example              environment variable template
│
├── case_study/                ← extended ContexTra (11 tools: +WEB_SEARCH, +CHECK_PACKAGE_STATUS)
│   ├── (same structure as contextra/)
│   └── .env.example              separate env template for case study
│
├── baselines/                 ← prompt-only LLM baselines (no tools)
│   ├── baseline1_minimal.py      B1: minimal prompt, CSV snippet only
│   └── baseline2_guided.py       B2: guided prompt with decision framework
│
├── eval/                      ← evaluation and table-reproduction scripts
│   ├── evaluate.py               confusion matrix, P/R/F1, chart generation
│   ├── rq1_table.py              RQ1: baselines vs ContexTra on Python 250
│   ├── rq2_table.py              RQ2: cross-model comparison on Python 250
│   ├── rq3_table.py              RQ3: cross-model comparison on Java 279
│   ├── rq4_table.py              RQ4: tool ablation on pilot 50
│   └── RQ2_latency_cdf.py        RQ2 latency CDF figure
│
├── data/
│   ├── alerts/                   input CSVs (static analyzer output)
│   │   ├── python_sample_demo.csv           7 alerts for bundled Python repos (demo)
│   │   ├── java_demo.csv                    30 alerts for bundled Java repo (demo)
│   │   ├── python_sample_250_proportional.csv  Python 250-alert sample (full reproduction)
│   │   ├── python_union_crypto_issues_usercode.csv  full Python 1521-alert dataset
│   │   └── java_unified_findings_279.csv    Java 279-alert dataset (full reproduction)
│   ├── ground_truth/             adjudicated labels
│   │   ├── Python_GROUND_TRUTH_FINAL.json   Python full GT (1522 entries; 1521 evaluated after dedup with CSV)
│   │   ├── python_sample_250_proportional_GT.json  Python 250-sample GT
│   │   ├── java_279_GT.json                 Java GT (286 entries; 279 evaluated after dedup with CSV)
│   │   └── pilot1_50_GT.json                RQ4 pilot GT (50 alerts)
│   ├── repos/                    bundled sample repositories (for demo runs)
│   │   ├── python/                  5 Python repos (7 alerts)
│   │   └── java/                    1 Java repo: jetty.project (30 alerts)
│   ├── callgraphs/               bundled sample call graphs
│   │   ├── python_sample_callgraph.json   110 entries for 5 Python repos
│   │   └── java_sample_callgraph.json     3298 entries for jetty.project
│   ├── codeql_dbs/               bundled sample CodeQL databases
│   │   ├── python/                  5 Python CodeQL DBs
│   │   └── java/                    1 Java CodeQL DB: jetty.project-db
│   └── (full dataset: see Data Availability below)
│
├── results/                   ← pre-computed result JSONs (canonical outputs)
│   ├── python/                   RQ1/RQ2 results (ContexTra + baselines × models)
│   ├── java/                     RQ3 results (ContexTra + baselines, Claude)
│   ├── ablation/                 RQ4 results (6/7/8/9-tool configs, pilot runs)
│   └── demo/                     output directory for demo runs
│
├── upstream/                  ← scripts used to generate the raw SAST alerts fed into ContexTra
│   ├── python/
│   │   ├── run_bandit_detector.py     run Bandit on all Python repos
│   │   ├── run_dlint_detector.py      run Dlint (flake8) on all Python repos
│   │   ├── run_semgrep_detector.py    run Semgrep on all Python repos
│   │   ├── filter_bandit_crypto.py    filter Bandit output to crypto-specific issues
│   │   ├── filter_dlint_crypto.py     filter Dlint output to crypto-specific issues
│   │   └── filter_semgrep_crypto.py   filter Semgrep output to crypto-specific issues
│   └── java/
│       ├── run_cryptoanalysis.sh      run CryptoAnalysis (CogniCrypt) on Java repos
│       ├── run_semgrep.sh             run Semgrep on Java repos
│       └── run_codeql.sh             run CodeQL crypto queries on Java repos
│
└── figures/                   ← pre-generated figures (RQ2 latency CDF, pilot confusion matrices)
```

## ContexTra Tool Set

The 9 investigation tools available to the agent:

| # | Tool | Description |
|---|------|-------------|
| 1 | `SEARCH` | Grep all source files for a regex pattern |
| 2 | `GET` | Read specific lines from a file |
| 3 | `GET_FUNCTION` | Extract complete function/method body |
| 4 | `GET_FILE` | Read entire file (≤100KB) |
| 5 | `LIST_DIRECTORY` | List files and subdirectories |
| 6 | `GET_SUBGRAPH` | Call graph: callers + callees at depth N |
| 7 | `GET_PREDECESSOR` | Call graph: callers only |
| 8 | `RUN_SEMGREP` | Run Semgrep static analysis (crypto/general/custom) |
| 9 | `RUN_CODEQL` | Run CodeQL data-flow analysis (crypto/general/custom) |

The case study extends this with `WEB_SEARCH` and `CHECK_PACKAGE_STATUS`.

## Ablation Configurations (RQ4)

The `contextra/` code supports these via the `--config` flag:

| Config | Tools | What's different |
|--------|-------|------------------|
| `9tool` | All 9 | Full ContexTra (default) |
| `8tool` | 8 | No SEARCH |
| `6tool` | 6 | No SEARCH, GET_FUNCTION, GET |
| `7tool_nosast` | 7 | No RUN_SEMGREP, RUN_CODEQL |
| `9tool_searchcap` | 9 | SEARCH capped at 3 calls per alert |

## How to Reproduce

### Prerequisites

- Python 3.9+
- An Anthropic API key (for Claude), or Ollama installed (for local models)

### Setup (one-time)

```bash
./run.sh setup
```

This automatically:
1. Creates a Python virtual environment (`.venv/`)
2. Installs all Python dependencies from `requirements.txt`
3. Installs Semgrep (for `RUN_SEMGREP` tool)
4. Checks for / installs ripgrep (for `SEARCH` tool)
5. Checks for / installs CodeQL CLI and downloads query packs (for `RUN_CODEQL` tool)
6. Creates `contextra/.env` from the template

After setup, edit `contextra/.env` and set your `ANTHROPIC_API_KEY`.

### Quick Demo (works out of the box — just needs an API key)

The artifact bundles 5 small Python repos (7 alerts) and 1 Java repo (30 alerts) with all supporting data (source code, call graphs, CodeQL databases). Run ContexTra end-to-end on them:

```bash
./run.sh demo-python      # 7 Python alerts, all 9 tools active
./run.sh demo-java        # 30 Java alerts (jetty.project)
./run.sh demo-ablation    # All 5 ablation configs on 7 Python alerts
```

### Reproducing Paper Tables (no setup needed — instant verification)

All result JSONs in `results/` are the actual outputs reported in the paper. These commands require only Python 3.9+ (no venv, no API key, no external tools):

```bash
./run.sh eval-all       # Run all four tables at once (recommended first step)

./run.sh eval-rq1       # RQ1 table: baselines vs ContexTra on Python 250
./run.sh eval-rq2       # RQ2 table: cross-model comparison on Python 250
./run.sh eval-rq3       # RQ3 table: cross-model comparison on Java 279
./run.sh eval-rq4       # RQ4 table: tool ablation on pilot 50
./run.sh eval-latency   # RQ2 latency CDF figure (requires matplotlib)
./run.sh eval-python    # Confusion matrix chart for Python (ContexTra-Claude)
./run.sh eval-java      # Confusion matrix chart for Java (ContexTra-Claude)
```

### Full Reproduction (requires full dataset)

Full reproduction requires all 915 Python / 19 Java source repositories, their call graphs, and CodeQL databases. The full dataset will be made available upon paper acceptance (see Data Availability).

Once obtained, organize the dataset into the following structure:

```
/path/to/full_dataset/
├── repos/
│   ├── python/           ← 915 Python repositories
│   └── java/             ← 19 Java repositories
├── callgraphs/
│   ├── python_callgraph.json
│   └── java_callgraph.json
└── codeql_dbs/
    ├── python/           ← Python CodeQL databases
    └── java/             ← Java CodeQL databases
```

Then point `run.sh` to it:

```bash
# Option 1: Set FULL_DATA_DIR (auto-resolves repos, callgraphs, CodeQL DBs)
FULL_DATA_DIR=/path/to/full_dataset ./run.sh rq1-python

# Option 2: Override individual paths
REPOS_DIR=/path/to/repos CALLGRAPH_JSON=/path/to/callgraph.json \
CODEQL_DBS_DIR=/path/to/dbs ./run.sh rq1-python
```

Available full reproduction targets:

```bash
./run.sh rq1-python     # ContexTra + B1 + B2 on Python 250-sample (Claude)
./run.sh rq2-llama      # ContexTra on Python 250-sample (Llama 3.3 70B)
./run.sh rq2-qwen       # ContexTra on Python 250-sample (Qwen 2.5-Coder 32B)
./run.sh rq3-java       # ContexTra + B1 + B2 on Java 279 (Claude)
./run.sh rq4-ablation   # All ablation configs on Python 250-sample
```

## LLM Models Used

| Model | Provider | Usage |
|-------|----------|-------|
| Claude Sonnet 4.5 | Anthropic (cloud) | RQ1, RQ2, RQ3, RQ4, case study |
| Llama 3.3 70B | Ollama (local, H100) | RQ2, RQ3 |
| Qwen 2.5-Coder 32B | Ollama (local, H100) | RQ2, RQ3 |

## Environment Variables

See `contextra/.env.example` for the full list. Key variables:

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic API key (required for Claude) |
| `LLM_PROVIDER` | `claude`, `openai`, or `ollama` |
| `LANGUAGE` | `python` or `java` (auto-selects repos, alerts, callgraphs, CodeQL DBs) |
| `DATA_DIR` | Artifact root directory (defaults to parent of `contextra/`) |
| `REPOS_DIR` | Override: path to source repositories |
| `ISSUES_CSV` | Override: path to alert CSV file |
| `CALLGRAPH_JSON` | Override: path to call graph JSON |
| `CODEQL_DBS_DIR` | Override: path to CodeQL databases |
| `FP_MAX_ITERATIONS` | Agent loop iteration cap (default: 15) |

For demo runs, all paths are set automatically by `run.sh`. Override variables are only needed for full reproduction with external data.

## Data Availability

### Bundled demo subset (in `data/`)

A representative subset is bundled in the artifact for immediate end-to-end demos without requiring external downloads:

| Language | Repos | Alerts Covered | Source Size | CodeQL DB Size |
|----------|-------|----------------|-------------|----------------|
| Python | 5 repos | 7 / 250 | ~65 KB | ~20 MB |
| Java | 1 repo (jetty.project) | 30 / 279 | ~66 MB | ~72 MB |

Each sample repo includes source code (no `.git` metadata), pre-computed call graph entries, and a pre-built CodeQL database. The `demo-*` targets use this bundled data automatically.

### Pre-computed results (in `results/`)

The full set of pre-computed result JSONs for every experiment is included in `results/`. This allows all paper tables and figures to be reproduced via `eval-*` targets **without re-running the agent and without any external data**.

### Full dataset

The complete evaluation spans 915 Python repositories (250 sampled alerts from 1,521 total) and 19 Java repositories (279 alerts). All repositories are publicly available open-source projects on GitHub. The full dataset (~7.5 GB including source repositories, pre-built CodeQL databases, and call graphs) exceeds the practical size limit for anonymous hosting and will be released publicly upon acceptance.

The bundled demo subset (37 alerts across 6 repos) and the pre-computed result JSONs are sufficient to verify all paper claims: `demo-*` targets demonstrate the agent end-to-end, and `eval-*` targets reproduce every table and figure from pre-computed outputs.

### Building data from scratch

The full dataset can be reconstructed from public sources:

1. **Source repositories:** Clone each repository listed in the `repo_name` column of the alert CSVs (`data/alerts/`). Python repo names follow the `owner_reponame` convention (e.g., `66ru_payback` → `github.com/66ru/payback`). Java repos are named directly (e.g., `jetty.project`).
2. **CodeQL databases:** Build per-repo databases using `codeql database create --language={python,java}`. Java repositories must be buildable (Maven/Gradle).
3. **Call graphs:**
   - **Python:** Generated using JarvisCG (`pip install jarviscg`), a Python call graph generator. The pipeline runs JarvisCG on all `.py` files per repo (up to 200, flagged files first), merges results into a unified per-repo callgraph, then enriches each function entry with callers, callees, and categorized calls (crypto/network/auth) via AST analysis. Output is the per-function JSON format consumed by `GET_SUBGRAPH`/`GET_PREDECESSOR` (see `data/callgraphs/` for the schema).
   - **Java:** Generated by running a CodeQL query (`callgraph_extract.ql`) on each repo's pre-built CodeQL database. The query uses `viableCallable()` for sound virtual-dispatch resolution, extracts all caller/callee pairs, and a post-processing script enriches them into the same per-function JSON format as Python.

## Upstream Alert Generation (`upstream/`)

The `upstream/` directory contains the scripts used to run the upstream static analysis tools that produce the raw alerts triaged by ContexTra. These are provided for full reproducibility of the alert generation pipeline.

### Python (`upstream/python/`)

The pipeline has two stages: **detection** (run tools) → **filtering** (extract crypto-specific alerts).

```bash
# Stage 1: Run each detector on all Python repos
python upstream/python/run_bandit_detector.py  --workdir /path/to/repos --output-dir ./bandit_results
python upstream/python/run_dlint_detector.py   --workdir /path/to/repos --output-dir ./dlint_results
python upstream/python/run_semgrep_detector.py --workdir /path/to/repos --output-dir ./semgrep_results

# Stage 2: Filter to crypto-specific issues only
python upstream/python/filter_bandit_crypto.py  --bandit-dir ./bandit_results  --output filtered_bandit.csv
python upstream/python/filter_dlint_crypto.py   --results-dir ./dlint_results  --db crypto_usage.db
python upstream/python/filter_semgrep_crypto.py --semgrep-dir ./semgrep_results --db crypto_usage.db
```

The filter scripts use curated lists of crypto-related rule IDs (e.g., Bandit B303/B304/B305, Dlint DUO123/DUO130, Semgrep `insecure-hash-algorithm`) derived from the NDSS'24 paper on cryptographic misuse reporting.

### Java (`upstream/java/`)

```bash
# Run CryptoAnalysis (CogniCrypt SAST) — requires built JARs and CryptoAnalysis tool
upstream/java/run_cryptoanalysis.sh

# Run Semgrep with Java crypto/security rules
upstream/java/run_semgrep.sh

# Run CodeQL with crypto-focused queries (CWE-327, CWE-330, CWE-780, CWE-798)
upstream/java/run_codeql.sh
```

All Java scripts use environment variables for tool paths (`JAVA_HOME`, `MAVEN_HOME`, `BASE_DIR`, `REPOS_DIR`, etc.) and auto-detect installed tools when not explicitly set. See each script's `CONFIGURATION` section for details.
