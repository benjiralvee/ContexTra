"""
config.py — System Configuration
=================================

All settings live here. Nothing is hardcoded elsewhere.
Configure via .env file or environment variables.


SWITCHING LLM PROVIDER:
    LLM_PROVIDER=claude   → Anthropic API  (needs ANTHROPIC_API_KEY)
    LLM_PROVIDER=openai   → OpenAI API     (needs OPENAI_API_KEY)
    LLM_PROVIDER=ollama   → Local Ollama   (needs OLLAMA_BASE_URL)

SWITCHING LANGUAGE:
    LANGUAGE=python  → data/repos/python/, data/alerts/python_sample_250_proportional.csv
    LANGUAGE=java    → data/repos/java/,   data/alerts/java_unified_findings_279.csv
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Set


# =====================================================
# .env Loading (optional — works without python-dotenv)
# =====================================================

try:
    from dotenv import load_dotenv

    # Look for .env in this directory, then in parent
    _here = Path(__file__).parent
    _env_file = _here / ".env"
    if not _env_file.exists():
        _env_file = _here.parent / ".env"
    if _env_file.exists():
        load_dotenv(_env_file)
except ImportError:
    # python-dotenv not installed — use raw environment variables
    pass


# =====================================================
# Helpers — read typed values from environment
# =====================================================

def _env(key: str, default: str = "") -> str:
    """Read a string environment variable."""
    return os.getenv(key, default)


def _env_bool(key: str, default: bool = False) -> bool:
    """Read a boolean env var. Accepts: true/1/yes (case-insensitive)."""
    return os.getenv(key, str(default)).strip().lower() in ("true", "1", "yes")


def _env_int(key: str, default: int = 0) -> int:
    """Read an integer env var with safe fallback."""
    try:
        return int(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float = 0.0) -> float:
    """Read a float env var with safe fallback."""
    try:
        return float(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


# =====================================================
# DATA CLASSES 
# =====================================================

@dataclass
class LLMConfig:
    """
    LLM provider settings.

    Supports three providers:
      "claude"  → Anthropic SDK (anthropic library)
      "openai"  → OpenAI SDK   (openai library)
      "ollama"  → Local models  (uses openai library with custom base_url,
                                  because Ollama exposes an OpenAI-compatible API)

    the connector should be GENERIC LLM. If I give it a local LLM, it runs local.
    """
    provider: str = "claude"                          # "claude" | "openai" | "ollama"
    model: str = "claude-sonnet-4-5-20250929"         # Model name
    api_key: str = ""                                 # API key (empty for ollama)
    base_url: str = ""                                # Custom endpoint URL
    max_tokens: int = 2000                            # Max tokens per response
    temperature: float = 0.0                          # Generation temperature
    reasoning_effort: str = "medium"                  # GPT-5 only: "low"/"medium"/"high"


@dataclass
class ToolLimits:
    """
    Safety limits for tool execution.
    Prevents runaway file reads and search explosions.
    """
    max_lines_per_get: int = 100                      # Max lines in one GET call
    max_get_file_bytes: int = 100_000                 # Max file size for GET_FILE (100KB)
    max_search_matches: int = 50                      # Max results from SEARCH
    context_lines: int = 12                           # Lines of context around flagged line
    search_max_file_bytes: int = 1_000_000            # Skip files > 1MB in SEARCH
    search_skip_dirs: Set[str] = field(default_factory=lambda: {
        ".git", "__pycache__", "venv", ".venv", "env", ".tox",
        "site-packages", "dist", "build", ".mypy_cache"
    })


@dataclass
class DataPaths:
    """
    Paths to data files and directories.

    Automatically selected based on LANGUAGE setting:
      python → data/repos/python/, data/alerts/python_*.csv, data/callgraphs/python_*.json
      java   → data/repos/java/,   data/alerts/java_*.csv,   data/callgraphs/java_*.json

    All paths can be overridden via environment variables (REPOS_DIR, ISSUES_CSV,
    CALLGRAPH_JSON, CODEQL_DBS_DIR).
    """
    data_dir: Path = field(default_factory=lambda: Path("."))
    repos_dir: Path = field(default_factory=lambda: Path("."))
    csv_file: Path = field(default_factory=lambda: Path("."))
    callgraph_file: Path = field(default_factory=lambda: Path("."))
    kb_file: Path = field(default_factory=lambda: Path("."))
    codeql_dbs_dir: Path = field(default_factory=lambda: Path("."))
    use_test_repos: bool = False
    # "repos" or "repos_test" — used by _normalize_filename() in tools.py
    # to strip the prefix from CSV filenames (e.g., "repos_test/repo_name/file.py" → "file.py")
    repos_prefix: str = "repos"


@dataclass
class SystemConfig:
    """
    Top-level config — the SINGLE object passed throughout the system.

    """
    llm: LLMConfig = field(default_factory=LLMConfig)
    tool_limits: ToolLimits = field(default_factory=ToolLimits)
    paths: DataPaths = field(default_factory=DataPaths)

    max_iterations: int = 15                          # Max agentic loop iterations (Detection Engine)
    fp_max_iterations: int = 15                      # Max agentic loop iterations (FP Identifier)
    mode: str = "conversation"                        # "stateless" | "conversation"
    debug: bool = False                               # Verbose tool execution logging

    # Target language — controls file extensions, function detection,
    # Semgrep rulesets, CodeQL query suites, and search skip-dirs.
    # "python" for Python repos, "java" for Java repos.
    # Everything should be workable for Java
    language: str = "python"

    # Ablation config name — controls which tools are active.
    # Valid: "9tool", "9tool_searchcap", "6tool", "8tool", "7tool_nosast"
    ablation_config: str = "9tool"

    # Static analysis tool versions (for display in prompt)
    tool_versions: Dict[str, str] = field(default_factory=lambda: {
        "bandit": "1.8.6",
        "semgrep": "1.x",
        "dlint": "0.14.x",
    })


# =====================================================
# FACTORY — Build config from environment
# =====================================================

def load_config() -> SystemConfig:
    """
    Build SystemConfig from environment variables / .env file.

    This is the SINGLE place that reads env vars.
    Everything else receives a typed SystemConfig object.

    Returns:
        SystemConfig with all settings populated
    """
    # --- LLM Provider ---
    provider = _env("LLM_PROVIDER", "claude")

    if provider == "claude":
        llm = LLMConfig(
            provider="claude",
            model=_env("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929"),
            api_key=_env("ANTHROPIC_API_KEY"),
            max_tokens=_env_int("LLM_MAX_TOKENS", 2000),
            temperature=_env_float("LLM_TEMPERATURE", 0.0),
        )
    elif provider == "openai":
        llm = LLMConfig(
            provider="openai",
            model=_env("OPENAI_MODEL", "gpt-5.1"),
            api_key=_env("OPENAI_API_KEY"),
            base_url=_env("OPENAI_BASE_URL"),
            max_tokens=_env_int("LLM_MAX_TOKENS", 2000),
            temperature=_env_float("LLM_TEMPERATURE", 0.0),
            reasoning_effort=_env("REASONING_EFFORT", "medium"),
        )
    elif provider == "ollama":
        llm = LLMConfig(
            provider="ollama",
            model=_env("OLLAMA_MODEL", "llama3.2:3b"),
            api_key="ollama",  # Ollama ignores API keys
            base_url=_env("OLLAMA_BASE_URL", "http://localhost:11434"),
            max_tokens=_env_int("LLM_MAX_TOKENS", 2000),
            temperature=_env_float("LLM_TEMPERATURE", 0.0),
        )
    else:
        raise ValueError(
            f"Unknown LLM_PROVIDER='{provider}'. "
            f"Must be 'claude', 'openai', or 'ollama'."
        )

    # --- Data Paths (auto-select based on language) ---
    # DATA_DIR defaults to the artifact root (parent of contextra/)
    data_dir = Path(_env("DATA_DIR", str(Path(__file__).parent.parent)))
    language = _env("LANGUAGE", "python")

    if language == "java":
        # ============================================================
        # JAVA paths — under data/
        # ============================================================
        paths = DataPaths(
            data_dir=data_dir / "data",
            repos_dir=Path(_env("REPOS_DIR", str(data_dir / "data" / "repos" / "java"))),
            csv_file=Path(_env("ISSUES_CSV", str(data_dir / "data" / "alerts" / "java_demo.csv"))),
            callgraph_file=Path(_env("CALLGRAPH_JSON", str(data_dir / "data" / "callgraphs" / "java_sample_callgraph.json"))),
            kb_file=Path(_env("KB_FILE", str(data_dir / "data" / "fp-identifier-KB.json"))),
            codeql_dbs_dir=Path(_env("CODEQL_DBS_DIR", str(data_dir / "data" / "codeql_dbs" / "java"))),
            use_test_repos=False,
            repos_prefix="repos",
        )
    else:
        # ============================================================
        # PYTHON paths — under data/
        # ============================================================
        paths = DataPaths(
            data_dir=data_dir / "data",
            repos_dir=Path(_env("REPOS_DIR", str(data_dir / "data" / "repos" / "python"))),
            csv_file=Path(_env("ISSUES_CSV", str(data_dir / "data" / "alerts" / "python_sample_demo.csv"))),
            callgraph_file=Path(_env("CALLGRAPH_JSON", str(data_dir / "data" / "callgraphs" / "python_sample_callgraph.json"))),
            kb_file=Path(_env("KB_FILE", str(data_dir / "data" / "fp-identifier-KB.json"))),
            codeql_dbs_dir=Path(_env("CODEQL_DBS_DIR", str(data_dir / "data" / "codeql_dbs" / "python"))),
            use_test_repos=False,
            repos_prefix="repos",
        )

    # --- Assemble ---
    return SystemConfig(
        llm=llm,
        tool_limits=ToolLimits(
            max_lines_per_get=_env_int("MAX_LINES_PER_GET", 100),
            max_get_file_bytes=_env_int("MAX_GET_FILE_BYTES", 100_000),
            max_search_matches=_env_int("MAX_SEARCH_MATCHES", 50),
            context_lines=_env_int("CONTEXT_LINES", 12),
            search_max_file_bytes=_env_int("SEARCH_MAX_FILE_BYTES", 1_000_000),
        ),
        paths=paths,
        max_iterations=_env_int("MAX_ITERATIONS", 15),
        fp_max_iterations=_env_int("FP_MAX_ITERATIONS", 15),
        mode=_env("MODE", "conversation"),
        debug=_env_bool("DEBUG", False),
        language=_env("LANGUAGE", "python"),
    )

