#!/usr/bin/env bash
# ============================================================================
# run.sh — Single entry point for the ContexTra artifact
# ============================================================================
#
# USAGE:
#   ./run.sh setup              # One-time: venv, deps, Semgrep, CodeQL
#   ./run.sh demo-python        # Run ContexTra on 7 bundled Python alerts
#   ./run.sh demo-java          # Run ContexTra on 30 bundled Java alerts
#   ./run.sh eval-all           # Reproduce all paper tables (no API needed)
#   ./run.sh --help             # Show all targets
#
# ============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}    $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail() { echo -e "${RED}[FAIL]${NC}  $1"; exit 1; }
info() { echo -e "${BOLD}$1${NC}"; }

# --- Paths ---
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${DATA_DIR:-$ROOT/data}"
VENV_DIR="$ROOT/.venv"

# Load contextra/.env if present so baselines and helper scripts see API keys.
if [ -f "$ROOT/contextra/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/contextra/.env"
  set +a
fi

# Pre-flight: ANTHROPIC_API_KEY must be set (and not the placeholder) for any
# Claude-using target. Call require_api_key claude before such targets.
require_api_key() {
  case "$1" in
    claude|anthropic)
      if [ -z "${ANTHROPIC_API_KEY:-}" ] || [ "$ANTHROPIC_API_KEY" = "sk-ant-your-key-here" ]; then
        fail "ANTHROPIC_API_KEY is not set. Edit contextra/.env and add your key, then rerun."
      fi
      ;;
  esac
}

# --- Resolve full-reproduction paths ---
# Priority: explicit env var > FULL_DATA_DIR (external) > data/ (bundled demo subset)
# Set FULL_DATA_DIR to the root of the full dataset (see README — Data Availability).
FULL_DATA_DIR="${FULL_DATA_DIR:-}"
resolve_repos_dir() {
  local lang="$1"
  if [ -n "${REPOS_DIR:-}" ]; then echo "$REPOS_DIR"
  elif [ -n "$FULL_DATA_DIR" ] && [ -d "$FULL_DATA_DIR/repos/$lang" ]; then echo "$FULL_DATA_DIR/repos/$lang"
  else echo "$DATA_DIR/repos/$lang"
  fi
}
resolve_callgraph() {
  local lang="$1"
  if [ -n "${CALLGRAPH_JSON:-}" ]; then echo "$CALLGRAPH_JSON"
  elif [ -n "$FULL_DATA_DIR" ] && [ -f "$FULL_DATA_DIR/callgraphs/${lang}_callgraph.json" ]; then echo "$FULL_DATA_DIR/callgraphs/${lang}_callgraph.json"
  else echo "$DATA_DIR/callgraphs/${lang}_sample_callgraph.json"
  fi
}
resolve_codeql_dbs() {
  local lang="$1"
  if [ -n "${CODEQL_DBS_DIR:-}" ]; then echo "$CODEQL_DBS_DIR"
  elif [ -n "$FULL_DATA_DIR" ] && [ -d "$FULL_DATA_DIR/codeql_dbs/$lang" ]; then echo "$FULL_DATA_DIR/codeql_dbs/$lang"
  else echo "$DATA_DIR/codeql_dbs/$lang"
  fi
}
resolve_csv() {
  local default_csv="$1"
  if [ -n "${ISSUES_CSV:-}" ]; then echo "$ISSUES_CSV"
  else echo "$default_csv"
  fi
}

usage() {
  cat <<EOF
Usage: $0 <target>

=== First-Time Setup ===
  setup              Create venv, install Python deps, Semgrep, check/install CodeQL

=== Demo Runs (works out of the box with bundled sample repos) ===
  demo-python        Run ContexTra on 7 bundled Python alerts (5 repos)
  demo-java          Run ContexTra on 30 bundled Java alerts (jetty.project)
  demo-ablation      Run all 5 ablation configs on 7 Python alerts

=== Reproduce Paper Tables (no API needed — uses pre-computed results/) ===
  eval-rq1           RQ1 table: baselines vs ContexTra on Python 250
  eval-rq2           RQ2 table: cross-model comparison on Python 250
  eval-rq3           RQ3 table: cross-model comparison on Java 279
  eval-rq4           RQ4 table: tool ablation on pilot 50
  eval-latency       RQ2 latency CDF figure (PDF/PNG)
  eval-python        General Python evaluation (confusion matrix chart)
  eval-java          General Java evaluation (confusion matrix chart)
  eval-all           Run all eval-rq* targets at once

=== Full Reproduction (requires full dataset — see README Data Availability) ===
  rq1-python         Run ContexTra + B1 + B2 on full Python 250-sample (Claude)
  rq2-llama          Run ContexTra on full Python 250-sample (Llama 3.3 70B)
  rq2-qwen           Run ContexTra on full Python 250-sample (Qwen 2.5-Coder 32B)
  rq3-java           Run ContexTra + B1 + B2 on full Java 279 dataset (Claude)
  rq4-ablation       Run all four ablation configs on full Python 250-sample

  Set FULL_DATA_DIR or individual overrides (REPOS_DIR, CALLGRAPH_JSON, CODEQL_DBS_DIR).
  Example: FULL_DATA_DIR=/path/to/dataset ./run.sh rq1-python
EOF
  exit 1
}

# ============================================================================
# HELPER: Activate venv (creates it if needed via 'setup')
# ============================================================================

activate_venv() {
  if [ -d "$VENV_DIR" ]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
  elif python3 --version &>/dev/null; then
    warn "No .venv found. Using system Python. Run './run.sh setup' for full tool support."
  else
    fail "Python 3 not found and no .venv. Run './run.sh setup' first."
  fi
}

activate_venv_strict() {
  if [ ! -d "$VENV_DIR" ]; then
    fail "Virtual environment not found. Run './run.sh setup' first."
  fi
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
}

get_python() {
  if [ -n "${VIRTUAL_ENV:-}" ]; then
    echo "python3"
  elif [ -f "$VENV_DIR/bin/python3" ]; then
    echo "$VENV_DIR/bin/python3"
  else
    echo "python3"
  fi
}

# ============================================================================
# TARGET: setup
# ============================================================================

do_setup() {
  echo ""
  info "============================================================"
  info "  ContexTra Artifact — Setup"
  info "============================================================"

  # --- Step 1: Check Python ---
  echo ""
  echo "--- Step 1: Checking Python ---"
  python3 --version >/dev/null 2>&1 || fail "Python 3 not found. Install Python 3.9+ from https://python.org"
  PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
  ok "Python $PY_VER"

  # --- Step 2: Create virtual environment ---
  echo ""
  echo "--- Step 2: Python Virtual Environment ---"
  if [ ! -d "$VENV_DIR" ]; then
    echo "  Creating virtual environment at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    ok "Virtual environment created"
  else
    ok "Virtual environment already exists at $VENV_DIR"
  fi
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"

  # --- Step 3: Install Python dependencies ---
  echo ""
  echo "--- Step 3: Installing Python Dependencies ---"
  pip install --quiet --upgrade pip
  pip install --quiet -r "$ROOT/requirements.txt"
  ok "Python dependencies installed (from requirements.txt)"

  # --- Step 4: Install Semgrep ---
  echo ""
  echo "--- Step 4: Semgrep ---"
  if command -v semgrep &>/dev/null; then
    SEMGREP_VER=$(semgrep --version 2>/dev/null || echo "unknown")
    ok "Semgrep already installed ($SEMGREP_VER)"
  else
    echo "  Installing Semgrep via pip..."
    pip install --quiet semgrep
    if command -v semgrep &>/dev/null; then
      ok "Semgrep installed ($(semgrep --version 2>/dev/null || echo 'ok'))"
    else
      warn "Semgrep installation failed. RUN_SEMGREP tool will be unavailable."
    fi
  fi

  # --- Step 5: Install ripgrep (for SEARCH tool) ---
  echo ""
  echo "--- Step 5: ripgrep ---"
  if command -v rg &>/dev/null; then
    ok "ripgrep already installed ($(rg --version | head -1))"
  else
    echo "  Installing ripgrep..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
      if command -v brew &>/dev/null; then
        brew install ripgrep && ok "ripgrep installed via Homebrew" || warn "ripgrep install failed. SEARCH tool will fall back to grep."
      else
        warn "Homebrew not found. Install ripgrep manually: https://github.com/BurntSushi/ripgrep#installation"
      fi
    elif command -v apt-get &>/dev/null; then
      sudo apt-get update -qq && sudo apt-get install -y -qq ripgrep \
        && ok "ripgrep installed via apt" \
        || warn "ripgrep install failed. SEARCH tool will fall back to grep."
    else
      warn "Could not auto-install ripgrep. Install manually: https://github.com/BurntSushi/ripgrep#installation"
    fi
  fi

  # --- Step 6: Install / check CodeQL ---
  echo ""
  echo "--- Step 6: CodeQL ---"
  CODEQL_BIN=""
  for loc in \
    "$(command -v codeql 2>/dev/null || true)" \
    /usr/local/codeql/codeql \
    /opt/codeql/codeql \
    "$HOME/.local/codeql/codeql"; do
    if [ -n "$loc" ] && [ -f "$loc" ] 2>/dev/null; then
      CODEQL_BIN="$loc"
      break
    fi
  done

  if [ -n "$CODEQL_BIN" ]; then
    ok "CodeQL found at $CODEQL_BIN"
  else
    echo "  CodeQL not found. Installing to ~/.local/codeql/ ..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
      CODEQL_PLATFORM="osx64"
    else
      CODEQL_PLATFORM="linux64"
    fi
    CODEQL_INSTALL_DIR="$HOME/.local/codeql"
    CODEQL_TMP=$(mktemp -d)
    if curl -L -o "$CODEQL_TMP/codeql.zip" \
        "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-${CODEQL_PLATFORM}.zip" 2>/dev/null; then
      mkdir -p "$(dirname "$CODEQL_INSTALL_DIR")"
      unzip -q -o "$CODEQL_TMP/codeql.zip" -d "$(dirname "$CODEQL_INSTALL_DIR")" 2>/dev/null \
        && CODEQL_BIN="$CODEQL_INSTALL_DIR/codeql" \
        || warn "Failed to extract CodeQL."
      rm -rf "$CODEQL_TMP"
      if [ -n "$CODEQL_BIN" ] && [ -f "$CODEQL_BIN" ]; then
        ok "CodeQL installed at $CODEQL_INSTALL_DIR"
      fi
    else
      warn "Failed to download CodeQL. RUN_CODEQL tool will be unavailable."
    fi
  fi

  if [ -n "$CODEQL_BIN" ] && [ -f "$CODEQL_BIN" ]; then
    echo "  Downloading CodeQL query packs (python + java)..."
    "$CODEQL_BIN" pack download codeql/python-queries 2>/dev/null \
      && ok "CodeQL Python query pack ready" \
      || warn "CodeQL Python query pack download failed."
    "$CODEQL_BIN" pack download codeql/java-queries 2>/dev/null \
      && ok "CodeQL Java query pack ready" \
      || warn "CodeQL Java query pack download failed."
  fi

  # --- Step 7: .env file ---
  echo ""
  echo "--- Step 7: Configuration ---"
  if [ -f "$ROOT/contextra/.env" ]; then
    ok "contextra/.env already exists"
  else
    cp "$ROOT/contextra/.env.example" "$ROOT/contextra/.env"
    ok "Created contextra/.env from .env.example"
    warn "Edit contextra/.env to add your ANTHROPIC_API_KEY before running demo targets."
  fi

  # --- Done ---
  echo ""
  info "============================================================"
  info "  Setup Complete!"
  info "============================================================"
  echo ""
  echo "  Next steps:"
  echo "    1. Edit contextra/.env and set ANTHROPIC_API_KEY"
  echo "    2. ./run.sh eval-all        # Reproduce paper tables (no API needed)"
  echo "    3. ./run.sh demo-python     # Run ContexTra on bundled sample alerts"
  echo ""
}

# ============================================================================
# MAIN DISPATCH
# ============================================================================

[[ $# -ge 1 ]] || usage

case "$1" in

  setup)
    do_setup
    ;;

  # ===========================================================================
  # DEMO RUNS — use bundled sample repos (works out of the box)
  # ===========================================================================

  demo-python)
    activate_venv_strict
    require_api_key claude
    PYTHON=$(get_python)
    echo "=== Demo: ContexTra (9-tool, Claude) on 7 bundled Python alerts ==="
    LANGUAGE=python \
    ISSUES_CSV="$DATA_DIR/alerts/python_sample_demo.csv" \
    REPOS_DIR="$DATA_DIR/repos/python" \
    CALLGRAPH_JSON="$DATA_DIR/callgraphs/python_sample_callgraph.json" \
    CODEQL_DBS_DIR="$DATA_DIR/codeql_dbs/python" \
    "$PYTHON" "$ROOT/contextra/main.py" \
      --provider claude --config 9tool --language python \
      --output "$ROOT/results/demo/demo_python_9tool.json"
    ;;

  demo-java)
    activate_venv_strict
    require_api_key claude
    PYTHON=$(get_python)
    echo "=== Demo: ContexTra (9-tool, Claude) on 30 bundled Java alerts ==="
    LANGUAGE=java \
    ISSUES_CSV="$DATA_DIR/alerts/java_demo.csv" \
    REPOS_DIR="$DATA_DIR/repos/java" \
    CALLGRAPH_JSON="$DATA_DIR/callgraphs/java_sample_callgraph.json" \
    CODEQL_DBS_DIR="$DATA_DIR/codeql_dbs/java" \
    "$PYTHON" "$ROOT/contextra/main.py" \
      --provider claude --config 9tool --language java \
      --output "$ROOT/results/demo/demo_java_9tool.json"
    ;;

  demo-ablation)
    activate_venv_strict
    require_api_key claude
    PYTHON=$(get_python)
    for cfg in 9tool 9tool_searchcap 8tool 7tool_nosast 6tool; do
      echo ""
      echo "=== Demo Ablation: $cfg on 7 bundled Python alerts ==="
      LANGUAGE=python \
      ISSUES_CSV="$DATA_DIR/alerts/python_sample_demo.csv" \
      REPOS_DIR="$DATA_DIR/repos/python" \
      CALLGRAPH_JSON="$DATA_DIR/callgraphs/python_sample_callgraph.json" \
      CODEQL_DBS_DIR="$DATA_DIR/codeql_dbs/python" \
      "$PYTHON" "$ROOT/contextra/main.py" \
        --provider claude --config "$cfg" --language python \
        --output "$ROOT/results/demo/demo_python_${cfg}.json"
    done
    ;;

  # ===========================================================================
  # REPRODUCE PAPER TABLES (from pre-computed results — no API needed)
  # ===========================================================================

  eval-rq1)
    activate_venv
    PYTHON=$(get_python)
    echo "=== RQ1 Table: B1, B2, ContexTra on Python 250 (Claude) ==="
    "$PYTHON" "$ROOT/eval/rq1_table.py" \
      --gt "$DATA_DIR/ground_truth/python_sample_250_proportional_GT.json" \
      --results "$ROOT/results/python/results_b1_claude_prop250.json" "B1 Minimal" \
      --results "$ROOT/results/python/results_b2_claude_prop250.json" "B2 Guided" \
      --results "$ROOT/results/python/results_claude_proportional_250.json" "ContexTra"
    ;;

  eval-rq2)
    activate_venv
    PYTHON=$(get_python)
    echo "=== RQ2 Table: Cross-model comparison on Python 250 ==="
    "$PYTHON" "$ROOT/eval/rq2_table.py" \
      --gt "$DATA_DIR/ground_truth/python_sample_250_proportional_GT.json" \
      --results "$ROOT/results/python/results_claude_proportional_250.json" "Claude Sonnet 4.5" \
      --results "$ROOT/results/python/results_contextra_llama33_70b_prop250.json" "Llama 3.3 70B" \
      --results "$ROOT/results/python/results_contextra_qwen25coder_32b_prop250.json" "Qwen2.5-Coder 32B"
    ;;

  eval-rq3)
    activate_venv
    PYTHON=$(get_python)
    echo "=== RQ3 Table: Cross-model comparison on Java 279 ==="
    "$PYTHON" "$ROOT/eval/rq3_table.py" \
      --gt "$DATA_DIR/ground_truth/java_279_GT.json" \
      --results "$ROOT/results/java/results_claude_java_279.json" "Claude Sonnet 4.5 (cloud)" \
      --results "$ROOT/results/java/results_llama3_3-70b_3616.json" "Llama 3.3 70B (local)" \
      --results "$ROOT/results/java/results_qwen2_5-coder-32b_3616.json" "Qwen2.5-Coder 32B (local)"
    ;;

  eval-rq4)
    activate_venv
    PYTHON=$(get_python)
    echo "=== RQ4 Table: Tool ablation on pilot 50 ==="
    "$PYTHON" "$ROOT/eval/rq4_table.py" \
      --gt "$DATA_DIR/ground_truth/pilot1_50_GT.json" \
      --results "$ROOT/results/ablation/pilot1_t0_9tool.json" "9-tool" \
      --results "$ROOT/results/ablation/pilot1_t0_9tool_searchcap.json" "9-tool + SEARCH cap" \
      --results "$ROOT/results/ablation/pilot1_t0_8tool.json" "8-tool" \
      --results "$ROOT/results/ablation/pilot1_t0_7tool_nosast.json" "7-tool (no SAST)" \
      --results "$ROOT/results/ablation/pilot1_t0_6tool.json" "6-tool"
    ;;

  eval-latency)
    activate_venv
    PYTHON=$(get_python)
    echo "=== RQ2 Latency CDF Figure ==="
    "$PYTHON" "$ROOT/eval/RQ2_latency_cdf.py"
    ;;

  eval-python)
    activate_venv
    PYTHON=$(get_python)
    echo "=== Evaluating Python results (chart) ==="
    "$PYTHON" "$ROOT/eval/evaluate.py" \
      "$ROOT/results/python/results_claude_proportional_250.json" \
      "$DATA_DIR/ground_truth/python_sample_250_proportional_GT.json" \
      --config-name "ContexTra-Claude-Python"
    ;;

  eval-java)
    activate_venv
    PYTHON=$(get_python)
    echo "=== Evaluating Java results (chart) ==="
    "$PYTHON" "$ROOT/eval/evaluate.py" \
      "$ROOT/results/java/results_claude_java_279.json" \
      "$DATA_DIR/ground_truth/java_279_GT.json" \
      --config-name "ContexTra-Claude-Java"
    ;;

  eval-all)
    echo "=== Running all eval targets ==="
    bash "$ROOT/run.sh" eval-rq1
    echo ""
    bash "$ROOT/run.sh" eval-rq2
    echo ""
    bash "$ROOT/run.sh" eval-rq3
    echo ""
    bash "$ROOT/run.sh" eval-rq4
    ;;

  # ===========================================================================
  # FULL REPRODUCTION (requires all repos cloned + CodeQL DBs built)
  # ===========================================================================

  rq1-python)
    activate_venv_strict
    require_api_key claude
    PYTHON=$(get_python)
    PY_CSV=$(resolve_csv "$DATA_DIR/alerts/python_sample_250_proportional.csv")
    PY_REPOS=$(resolve_repos_dir python)
    PY_CG=$(resolve_callgraph python)
    PY_CODEQL=$(resolve_codeql_dbs python)
    echo "=== RQ1: ContexTra (9-tool, Claude) on Python 250-sample ==="
    echo "  Repos:     $PY_REPOS"
    echo "  Callgraph: $PY_CG"
    echo "  CodeQL:    $PY_CODEQL"
    echo "  CSV:       $PY_CSV"
    LANGUAGE=python \
    ISSUES_CSV="$PY_CSV" \
    REPOS_DIR="$PY_REPOS" \
    CALLGRAPH_JSON="$PY_CG" \
    CODEQL_DBS_DIR="$PY_CODEQL" \
    "$PYTHON" "$ROOT/contextra/main.py" \
      --provider claude --config 9tool --language python \
      --output "$ROOT/results/python/results_claude_proportional_250.json"

    echo "=== RQ1: Baseline B1 (Claude) ==="
    "$PYTHON" "$ROOT/baselines/baseline1_minimal.py" \
      --input "$PY_CSV" \
      --output "$ROOT/results/python/results_b1_claude_prop250.json" \
      --llm claude

    echo "=== RQ1: Baseline B2 (Claude) ==="
    "$PYTHON" "$ROOT/baselines/baseline2_guided.py" \
      --input "$PY_CSV" \
      --output "$ROOT/results/python/results_b2_claude_prop250.json" \
      --llm claude
    ;;

  rq2-llama)
    activate_venv_strict
    PYTHON=$(get_python)
    PY_CSV=$(resolve_csv "$DATA_DIR/alerts/python_sample_250_proportional.csv")
    PY_REPOS=$(resolve_repos_dir python)
    PY_CG=$(resolve_callgraph python)
    PY_CODEQL=$(resolve_codeql_dbs python)
    echo "=== RQ2: ContexTra (Llama 3.3 70B) on Python 250-sample ==="
    echo "  Repos:     $PY_REPOS"
    echo "  Callgraph: $PY_CG"
    LANGUAGE=python \
    ISSUES_CSV="$PY_CSV" \
    REPOS_DIR="$PY_REPOS" \
    CALLGRAPH_JSON="$PY_CG" \
    CODEQL_DBS_DIR="$PY_CODEQL" \
    "$PYTHON" "$ROOT/contextra/main.py" \
      --provider ollama --model llama3.3:70b --config 9tool --language python \
      --output "$ROOT/results/python/results_contextra_llama33_70b_prop250.json"
    ;;

  rq2-qwen)
    activate_venv_strict
    PYTHON=$(get_python)
    PY_CSV=$(resolve_csv "$DATA_DIR/alerts/python_sample_250_proportional.csv")
    PY_REPOS=$(resolve_repos_dir python)
    PY_CG=$(resolve_callgraph python)
    PY_CODEQL=$(resolve_codeql_dbs python)
    echo "=== RQ2: ContexTra (Qwen 2.5-Coder 32B) on Python 250-sample ==="
    echo "  Repos:     $PY_REPOS"
    echo "  Callgraph: $PY_CG"
    LANGUAGE=python \
    ISSUES_CSV="$PY_CSV" \
    REPOS_DIR="$PY_REPOS" \
    CALLGRAPH_JSON="$PY_CG" \
    CODEQL_DBS_DIR="$PY_CODEQL" \
    "$PYTHON" "$ROOT/contextra/main.py" \
      --provider ollama --model qwen2.5-coder:32b --config 9tool --language python \
      --output "$ROOT/results/python/results_contextra_qwen25coder_32b_prop250.json"
    ;;

  rq3-java)
    activate_venv_strict
    require_api_key claude
    PYTHON=$(get_python)
    JV_CSV=$(resolve_csv "$DATA_DIR/alerts/java_unified_findings_279.csv")
    JV_REPOS=$(resolve_repos_dir java)
    JV_CG=$(resolve_callgraph java)
    JV_CODEQL=$(resolve_codeql_dbs java)
    echo "=== RQ3: ContexTra (Claude) on Java 279 ==="
    echo "  Repos:     $JV_REPOS"
    echo "  Callgraph: $JV_CG"
    echo "  CodeQL:    $JV_CODEQL"
    echo "  CSV:       $JV_CSV"
    LANGUAGE=java \
    ISSUES_CSV="$JV_CSV" \
    REPOS_DIR="$JV_REPOS" \
    CALLGRAPH_JSON="$JV_CG" \
    CODEQL_DBS_DIR="$JV_CODEQL" \
    "$PYTHON" "$ROOT/contextra/main.py" \
      --provider claude --config 9tool --language java \
      --output "$ROOT/results/java/results_claude_java_279.json"

    echo "=== RQ3: Baseline B1 (Claude, Java) ==="
    "$PYTHON" "$ROOT/baselines/baseline1_minimal.py" \
      --input "$JV_CSV" \
      --output "$ROOT/results/java/results_b1_claude_java_279.json" \
      --llm claude

    echo "=== RQ3: Baseline B2 (Claude, Java) ==="
    "$PYTHON" "$ROOT/baselines/baseline2_guided.py" \
      --input "$JV_CSV" \
      --output "$ROOT/results/java/results_b2_claude_java_279.json" \
      --llm claude
    ;;

  rq4-ablation)
    activate_venv_strict
    require_api_key claude
    PYTHON=$(get_python)
    PY_CSV=$(resolve_csv "$DATA_DIR/alerts/python_sample_250_proportional.csv")
    PY_REPOS=$(resolve_repos_dir python)
    PY_CG=$(resolve_callgraph python)
    PY_CODEQL=$(resolve_codeql_dbs python)
    echo "=== RQ4: Full ablation on Python 250-sample ==="
    echo "  Repos:     $PY_REPOS"
    echo "  Callgraph: $PY_CG"
    for cfg in 8tool 6tool 7tool_nosast 9tool_searchcap; do
      echo ""
      echo "=== RQ4: Ablation — $cfg ==="
      LANGUAGE=python \
      ISSUES_CSV="$PY_CSV" \
      REPOS_DIR="$PY_REPOS" \
      CALLGRAPH_JSON="$PY_CG" \
      CODEQL_DBS_DIR="$PY_CODEQL" \
      "$PYTHON" "$ROOT/contextra/main.py" \
        --provider claude --config "$cfg" --language python \
        --output "$ROOT/results/ablation/results_ablation_${cfg}.json"
    done
    ;;

  --help|-h)
    usage
    ;;

  *)
    usage
    ;;
esac
