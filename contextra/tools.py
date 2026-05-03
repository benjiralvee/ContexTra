"""
tools.py — Tool Executors
==========================

All tools the LLM can call during investigation.
Language-aware: works for both Python and Java repos.

EXISTING TOOLS (7):
    GET(filename, line_start, line_end)       — Read specific lines from a file
    GET_FILE(filename)                        — Read entire file (max 100KB)
    GET_FUNCTION(filename, line_number)       — Get complete function/method containing a line
    SEARCH(pattern, max_matches)              — Find pattern across all source files in repo
    LIST_DIRECTORY(directory)                 — List files and subdirectories
    GET_SUBGRAPH(node, depth)                 — Get call graph around a function
    GET_PREDECESSOR(node)                     — Get all callers of a function

SAST TOOLS (2):
    RUN_SEMGREP(mode, custom_rule)            — Run Semgrep on the repo
    RUN_CODEQL(mode, custom_query)            — Run CodeQL on the repo

The LLM uses these tools to gather evidence before classifying an issue.

LANGUAGE SUPPORT:
    config.language = "python" → searches *.py, detects def/async def, uses 19 targeted crypto rule dirs
    config.language = "java"   → searches *.java, detects Java methods, uses 10 targeted crypto rule dirs
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).parent))

from config import SystemConfig, ToolLimits


# =====================================================
# LANGUAGE-SPECIFIC CONSTANTS
# =====================================================
# Maps config.language → file extensions, Semgrep rulesets,
# CodeQL query suites, and extra directories to skip.

_LANG_FILE_EXTENSIONS = {
    "python": {".py"},
    "java": {".java"},
}

_LANG_GLOB_PATTERNS = {
    "python": ["*.py"],
    "java": ["*.java"],
}

# Additional dirs to skip during SEARCH (language-specific)
_LANG_EXTRA_SKIP_DIRS = {
    "python": set(),
    "java": {"target", "build", ".gradle", ".mvn", "bin", "out"},
}

# Semgrep crypto-specific rule configs per language.
# p/python-crypto does NOT exist (HTTP 404). p/security-audit misses many crypto
# findings (e.g. MD5-as-password). Instead we use targeted r/... rule directories
# that cover: weak hashes, insecure ciphers, weak SSL/TLS, insecure transport,
# insufficient key sizes, hardcoded secrets, JWT issues, and framework-specific
# crypto misuse (Django/Flask secret key leakage, insecure UUIDs, cleartext
# transmission, hardcoded AWS tokens).
# NOTE: Libraries like PyNaCl, pyOpenSSL, M2Crypto, tlslite have zero Semgrep
# rules. The LLM can use mode="custom" to write rules for those.
_LANG_SEMGREP_CRYPTO: dict = {
    "python": [
        "r/python.lang.security.insecure-hash-algorithms",
        "r/python.lang.security.insecure-hash-function",
        "r/python.lang.security.audit.weak-ssl-version",
        "r/python.lang.security.audit.md5-used-as-password",
        "r/python.lang.security.audit.sha224-hash",
        "r/python.lang.security.audit.ssl-wrap-socket-is-deprecated",
        "r/python.lang.security.audit.insecure-transport",
        "r/python.lang.security.unverified-ssl-context",
        "r/python.requests.security.disabled-cert-validation",
        "r/python.pycryptodome.security",
        "r/python.cryptography.security",
        "r/python.lang.security.audit.hardcoded-password-default-argument",
        "r/python.lang.security.audit.network",
        "r/python.jwt.security",
        "r/python.django.security.hashids-with-django-secret",
        "r/python.flask.security.hashids-with-flask-secret",
        "r/python.lang.security.insecure-uuid-version",
        "r/python.distributed.security",
        "r/python.boto3.security.hardcoded-token",
    ],
    "java": [
        "r/java.lang.security.audit.crypto",
        "r/java.lang.security.audit.weak-ssl-context",
        "r/java.lang.security.audit.md5-used-as-password",
        "r/java.lang.security.audit.blowfish-insufficient-key-size",
        "r/java.lang.security.audit.insecure-smtp-connection",
        "r/java.lang.security.audit.cbc-padding-oracle",
        "r/java.java-jwt.security",
        "r/java.jjwt.security",
        "r/java.servlets.security.cookie-issecure-false",
        "r/java.servlets.security.cookie-setSecure",
    ],
}

# CodeQL query suites per language (crypto mode)
_LANG_CODEQL_CRYPTO = {
    "python": "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
    "java": "codeql/java-queries:codeql-suites/java-security-and-quality.qls",
}

# CodeQL query suites per language (general mode)
_LANG_CODEQL_GENERAL = {
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
}

# CodeQL language name (for database creation hints)
_LANG_CODEQL_LANG = {
    "python": "python",
    "java": "java",
}

# Java method signature pattern — used by GET_FUNCTION for Java repos
# Matches: [annotations] [modifiers] ReturnType methodName(
# Examples:
#   public static void main(
#   private Map<String, List<Integer>> processData(
#   protected synchronized boolean validate(
#   @Override public String toString(
_JAVA_METHOD_RE = re.compile(
    r'^\s*'
    r'(?:@\w+(?:\s*\([^)]*\))?\s+)*'                           # optional annotations
    r'(?:(?:public|private|protected)\s+)?'                      # optional access modifier
    r'(?:(?:static|final|abstract|synchronized|native|default|strictfp)\s+)*'  # other modifiers
    r'(?:void|int|long|short|byte|char|float|double|boolean'     # primitive return types
    r'|[A-Z]\w*(?:\s*<[^>]*>)?(?:\s*\[\s*\])*)\s+'             # or class return types
    r'(\w+)\s*\('                                                # method name + open paren
)

# Java constructor pattern: [modifiers] ClassName(
_JAVA_CONSTRUCTOR_RE = re.compile(
    r'^\s*'
    r'(?:(?:public|private|protected)\s+)?'
    r'([A-Z]\w*)\s*\('                                          # ClassName(
)


class ToolExecutor:
    """
    Executes tools for the agentic LLM system.

    Each tool:
      1. Receives parameters from the LLM's JSON response
      2. Performs a deterministic operation (file read, search, etc.)
      3. Returns a result dict with either {"success": True, ...} or {"error": "..."}

    Tools are like functions. These are deterministic.
           You give it an input, it returns you back an output."
    """

    def __init__(self, config: SystemConfig, call_graphs: Dict[str, Dict]):
        """
        Initialize ToolExecutor.

        Args:
            config:      SystemConfig with paths and tool limits
            call_graphs: Dict mapping issue_id → call graph data
                         (loaded from callgraph_jarvis_ALL_FUNCTIONS.json)
        """
        self.config = config
        self.repos_dir = config.paths.repos_dir          # e.g., .../repos_test/
        self.repos_prefix = config.paths.repos_prefix      # "repos" or "repos_test"
        self.limits = config.tool_limits
        self.call_graphs = call_graphs
        self.language = config.language                    # "python" or "java"
        self.ablation_config = getattr(config, "ablation_config", "9tool")

        # SEARCH cap + dedup state (only active for 9tool_searchcap)
        self._search_count: int = 0
        self._search_cache: Dict[tuple, Dict] = {}
        self._current_issue_id: Optional[str] = None

        # Pre-compute language-specific settings (avoid repeated dict lookups)
        self._file_extensions = _LANG_FILE_EXTENSIONS.get(self.language, {".py"})
        self._glob_patterns = _LANG_GLOB_PATTERNS.get(self.language, ["*.py"])
        self._extra_skip_dirs = _LANG_EXTRA_SKIP_DIRS.get(self.language, set())
        self._all_skip_dirs = self.limits.search_skip_dirs | self._extra_skip_dirs

    # ==========================================================
    # FILENAME NORMALIZATION
    # ==========================================================
    # The CSV stores filenames with prefixes like:
    #   Main:  "repo_name/path/to/file.py"
    #   Test:  "repos_test/repo_name/path/to/file.py"
    # But our file system is: repos_dir / repo_name / path/to/file.py
    # So we need to strip the prefix to get just "path/to/file.py".

    def normalize_filename(self, filename: str, repo_name: str) -> str:
        """
        Strip repo/directory prefixes from a filename.

        Examples:
            "repos_test/my_repo/utils/auth.py"  →  "utils/auth.py"
            "my_repo/utils/auth.py"              →  "utils/auth.py"
            "utils/auth.py"                      →  "utils/auth.py"  (unchanged)
        """
        if not filename:
            return filename

        filename = filename.lstrip("./")

        # Strip "repos_test/repo_name/" or "repos/repo_name/" prefix
        prefix_with_repos = f"{self.repos_prefix}/{repo_name}/"
        # Strip "repo_name/" prefix
        prefix_without_repos = f"{repo_name}/"

        if filename.startswith(prefix_with_repos):
            filename = filename[len(prefix_with_repos):]
        elif filename.startswith(prefix_without_repos):
            filename = filename[len(prefix_without_repos):]

        return filename

    # ==========================================================
    # TOOL SIGNATURE (for duplicate detection)
    # ==========================================================
    # If the LLM requests the same tool with the same params 3 times,
    # we know it's stuck and should stop.

    def tool_signature(self, command: str, parameters: Dict[str, Any],
                       repo_name: str) -> str:
        """
        Create a stable signature for a tool call (for duplicate detection).
        Normalizes filenames so the same file requested differently still matches.
        """
        params = dict(parameters or {})
        # Normalize filename so GET("repo_name/file.py") == GET("file.py")
        if command in {"GET", "GET_FILE", "GET_FUNCTION"} and "filename" in params:
            params["filename"] = self.normalize_filename(
                str(params["filename"]), repo_name
            )
        # Sort keys for stable comparison
        items = ",".join(f"{k}={params[k]}" for k in sorted(params.keys()))
        return f"{command}|{items}"

    # ==========================================================
    # TOOL RESULT SUMMARY (for logging)
    # ==========================================================

    def summarize_result(self, command: str, result: Dict[str, Any]) -> str:
        """
        Create a concise one-line summary of a tool result.
        Used for tool_call_history in the output JSON (for paper analysis).
        """
        if "error" in result:
            return f"ERROR: {result['error']}"
        if not result.get("success"):
            return "Failed (no success flag)"

        # --- Command-specific summaries (using comprehension style) ---
        summaries = {
            "GET": lambda r: (
                f"Retrieved {r.get('num_lines', 0)} lines from "
                f"{r.get('filename', '?')}:{r.get('line_start', '?')}-{r.get('line_end', '?')}"
            ),
            "GET_FILE": lambda r: (
                f"Retrieved file {r.get('filename', '?')} "
                f"({r.get('size_bytes', 0)} bytes"
                f"{' truncated' if r.get('truncated') else ''})"
            ),
            "GET_FUNCTION": lambda r: (
                f"Retrieved function '{r.get('function_name', '?')}' "
                f"({r.get('num_lines', 0)} lines)"
            ),
            "SEARCH": lambda r: (
                f"Found {r.get('num_matches', 0)} matches for '{r.get('pattern', '?')}'"
                + (": " + ", ".join(
                    f"{m['filename']}:{m['line_number']}"
                    for m in r.get("matches", [])[:5]
                ) if r.get("matches") else "")
            ),
            "LIST_DIRECTORY": lambda r: (
                f"Listed '{r.get('directory', '.')}': "
                f"{len(r.get('directories', []))} dirs, "
                f"{len(r.get('source_files', r.get('python_files', [])))} source files"
            ),
            "GET_SUBGRAPH": lambda r: (
                f"Subgraph for '{r.get('node', '?')}': "
                f"{r.get('num_callers', 0)} callers, {r.get('num_callees', 0)} callees"
            ),
            "GET_PREDECESSOR": lambda r: (
                f"Predecessors for '{r.get('node', '?')}': "
                f"{r.get('num_callers', 0)} callers"
            ),
            "RUN_SEMGREP": lambda r: (
                f"Semgrep ({r.get('mode', '?')}): exit code {r.get('exit_code', '?')}"
            ),
            "RUN_CODEQL": lambda r: (
                f"CodeQL ({r.get('mode', '?')}): exit code {r.get('exit_code', '?')}"
            ),
        }

        fn = summaries.get(command)
        return fn(result) if fn else "Success"

    # ==========================================================
    # MAIN ROUTER — dispatches to the correct tool
    # ==========================================================

    def execute(self, command: str, parameters: Dict[str, Any],
                repo_name: str, issue_id: str) -> Dict[str, Any]:
        """
        Execute a tool command. Routes to the appropriate method.

        Args:
            command:    Tool name (e.g., "GET", "SEARCH", "RUN_SEMGREP")
            parameters: Tool parameters from LLM's JSON
            repo_name:  Repository name
            issue_id:   Current issue ID (for call graph lookups)

        Returns:
            Dict with {"success": True, ...} or {"error": "..."}
        """
        if self.config.debug:
            print(f"\n{'='*60}")
            print(f"🔧 TOOL: {command}")
            print(f"📋 PARAMS: {json.dumps(parameters, indent=2)}")
            print(f"{'='*60}")

        # Reset SEARCH cap/dedup when starting a new issue
        if self.ablation_config == "9tool_searchcap" and issue_id != self._current_issue_id:
            self._search_count = 0
            self._search_cache = {}
            self._current_issue_id = issue_id

        router = {
            "GET":            lambda: self._exec_get(parameters, repo_name),
            "GET_FILE":       lambda: self._exec_get_file(parameters, repo_name),
            "GET_FUNCTION":   lambda: self._exec_get_function(parameters, repo_name),
            "SEARCH":         lambda: self._exec_search(parameters, repo_name),
            "LIST_DIRECTORY":  lambda: self._exec_list_directory(parameters, repo_name),
            "GET_SUBGRAPH":   lambda: self._exec_get_subgraph(parameters, issue_id, repo_name),
            "GET_PREDECESSOR": lambda: self._exec_get_predecessor(parameters, issue_id, repo_name),
            "RUN_SEMGREP":    lambda: self._exec_run_semgrep(parameters, repo_name),
            "RUN_CODEQL":     lambda: self._exec_run_codeql(parameters, repo_name),
        }

        executor = router.get(command)
        if executor is None:
            return {"error": f"Unknown command: {command}. Available: {', '.join(router.keys())}"}

        return executor()

    # ==========================================================
    # TOOL: GET — Read specific lines from a file
    # ==========================================================

    def _exec_get(self, params: Dict, repo_name: str) -> Dict[str, Any]:
        """
        GET(filename, line_start, line_end)

        Read specific lines from a file. Lines are 1-indexed.
        Clamps to max_lines_per_get if range is too large.
        Returns formatted lines with line numbers.
        """
        filename = params.get("filename")
        if not filename:
            return {"error": "filename is required"}

        # Parse line range (both optional — defaults to first 50 lines)
        try:
            line_start = int(params.get("line_start", 1))
            line_end = int(params.get("line_end", line_start + 50))
        except (TypeError, ValueError):
            return {"error": "line_start and line_end must be integers"}

        # Normalize filename (strip repo prefix)
        filename = self.normalize_filename(filename, repo_name)

        # Resolve paths and security check
        file_path = (self.repos_dir / repo_name / filename).resolve()
        repo_path = (self.repos_dir / repo_name).resolve()
        try:
            file_path.relative_to(repo_path)
        except ValueError:
            return {"error": "Access denied: file outside repository boundaries"}

        if line_start < 1 or line_end < line_start:
            return {"error": "Invalid line range (line_start >= 1, line_end >= line_start)"}

        # Clamp range to limit
        requested_end = line_end
        clamped = False
        if (line_end - line_start + 1) > self.limits.max_lines_per_get:
            line_end = line_start + self.limits.max_lines_per_get - 1
            clamped = True

        if not file_path.exists():
            return {"error": f"File not found: {filename}"}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            if line_start > len(lines):
                return {"error": f"line_start ({line_start}) exceeds file length ({len(lines)})"}

            result_lines = lines[line_start - 1 : line_end]
            # Format with line numbers (e.g., "  42  content")
            formatted = [
                f"{line_start + i:4d}  {line.rstrip()}"
                for i, line in enumerate(result_lines)
            ]

            return {
                "success": True,
                "filename": filename,
                "line_start": line_start,
                "line_end": line_end,
                "requested_line_end": requested_end,
                "clamped": clamped,
                "content": "\n".join(formatted),
                "num_lines": len(result_lines),
            }
        except Exception as e:
            return {"error": f"Error reading file: {e}"}

    # ==========================================================
    # TOOL: GET_FILE — Read entire file
    # ==========================================================

    def _exec_get_file(self, params: Dict, repo_name: str) -> Dict[str, Any]:
        """
        GET_FILE(filename)

        Read entire file contents, truncated at max_get_file_bytes (100KB).
        """
        filename = params.get("filename")
        if not filename:
            return {"error": "filename is required"}

        filename = self.normalize_filename(filename, repo_name)

        file_path = (self.repos_dir / repo_name / filename).resolve()
        repo_path = (self.repos_dir / repo_name).resolve()
        try:
            file_path.relative_to(repo_path)
        except ValueError:
            return {"error": "Access denied: file outside repository boundaries"}

        if not file_path.exists():
            return {"error": f"File not found: {filename}"}

        size_bytes = file_path.stat().st_size
        truncated = False

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                if size_bytes > self.limits.max_get_file_bytes:
                    content = f.read(self.limits.max_get_file_bytes)
                    truncated = True
                else:
                    content = f.read()

            return {
                "success": True,
                "filename": filename,
                "content": content,
                "size_bytes": size_bytes,
                "truncated": truncated,
                "note": (
                    "GET_FILE was truncated; use SEARCH + GET(line ranges) for targeted context"
                    if truncated else ""
                ),
            }
        except Exception as e:
            return {"error": f"Error reading file: {e}"}

    # ==========================================================
    # TOOL: GET_FUNCTION — Get complete function containing a line
    # ==========================================================

    def _exec_get_function(self, params: Dict, repo_name: str) -> Dict[str, Any]:
        """
        GET_FUNCTION(filename, line_number)

        Finds the function/method definition that contains the given line,
        then returns the complete function with line numbers.

        Language-aware:
            python → searches backwards for 'def ' or 'async def ',
                     finds end by indentation tracking
            java   → searches backwards for Java method/constructor signature,
                     finds end by brace { } balance tracking
        """
        filename = params.get("filename")
        if not filename:
            return {"error": "filename is required"}

        try:
            line_number = int(params.get("line_number", 0))
        except (TypeError, ValueError):
            return {"error": "line_number must be an integer"}

        filename = self.normalize_filename(filename, repo_name)

        file_path = (self.repos_dir / repo_name / filename).resolve()
        repo_path = (self.repos_dir / repo_name).resolve()
        try:
            file_path.relative_to(repo_path)
        except ValueError:
            return {"error": "Access denied: file outside repository boundaries"}

        if not file_path.exists():
            return {"error": f"File not found: {filename}"}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            if line_number < 1 or line_number > len(lines):
                return {"error": f"line_number {line_number} out of range (file has {len(lines)} lines)"}

            # Dispatch to language-specific function finder
            if self.language == "java":
                func_start, func_end, func_name = self._find_java_method(lines, line_number)
            else:
                func_start, func_end, func_name = self._find_python_function(lines, line_number)

            if func_start is None:
                return {"error": f"Could not find function/method definition before line {line_number}"}

            # Format with line numbers, marking the flagged line with >>>
            formatted = [
                f"{i+1:4d}{' >>> ' if i+1 == line_number else '     '}{lines[i].rstrip()}"
                for i in range(func_start - 1, func_end)
            ]

            return {
                "success": True,
                "filename": filename,
                "function_name": func_name,
                "function_start": func_start,
                "function_end": func_end,
                "num_lines": func_end - func_start + 1,
                "content": "\n".join(formatted),
            }
        except Exception as e:
            return {"error": f"Error reading file: {e}"}

    # ----------------------------------------------------------
    # Python function finder (indentation-based)
    # ----------------------------------------------------------

    @staticmethod
    def _find_python_function(lines: List[str], line_number: int):
        """
        Find the Python function containing line_number.

        Returns:
            (func_start, func_end, func_name) — all 1-indexed.
            func_end is exclusive (like range).
            Returns (None, None, None) if no function found.
        """
        # Step 1: Search backwards for 'def ' or 'async def '
        func_start = None
        func_name = None
        for i in range(line_number - 1, -1, -1):
            stripped = lines[i].lstrip()
            if stripped.startswith("def ") or stripped.startswith("async def "):
                func_start = i + 1   # 1-indexed
                func_name = lines[i].strip()
                break

        if func_start is None:
            return None, None, None

        # Step 2: Find function end (track indentation)
        base_indent = len(lines[func_start - 1]) - len(lines[func_start - 1].lstrip())
        func_end = len(lines)

        for i in range(func_start, len(lines)):
            line = lines[i]
            if line.strip() == "":
                continue  # Skip blank lines
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= base_indent and i > func_start:
                func_end = i
                break

        return func_start, func_end, func_name

    # ----------------------------------------------------------
    # Java method finder (brace-balance-based)
    # ----------------------------------------------------------

    @staticmethod
    def _find_java_method(lines: List[str], line_number: int):
        """
        Find the Java method/constructor containing line_number.

        Strategy:
          1. Search backwards for a line matching a Java method signature
             (access modifiers + return type + name + open paren)
          2. Track { } brace balance forward to find the closing }

        Returns:
            (func_start, func_end, func_name) — all 1-indexed.
            func_end is exclusive (like range).
            Returns (None, None, None) if no method found.
        """
        # Control flow keywords — these have parens but are NOT method declarations
        _JAVA_CONTROL_KEYWORDS = {"if", "else", "for", "while", "switch",
                                   "catch", "try", "return", "throw", "new"}

        # Step 1: Search backwards for method/constructor start
        func_start = None
        func_name = None
        for i in range(line_number - 1, -1, -1):
            line = lines[i]
            stripped = line.strip()

            # Skip empty lines, comments, annotations
            if (not stripped or stripped.startswith("//")
                    or stripped.startswith("/*") or stripped.startswith("*")):
                continue

            # Try Java method pattern (public static void foo(...))
            m = _JAVA_METHOD_RE.match(line)
            if m:
                func_start = i + 1  # 1-indexed
                func_name = m.group(1)
                break

            # Try Java constructor pattern (ClassName(...))
            m2 = _JAVA_CONSTRUCTOR_RE.match(line)
            if m2:
                # Make sure first word is not a control keyword
                first_word = stripped.split()[0] if stripped.split() else ""
                if first_word not in _JAVA_CONTROL_KEYWORDS:
                    func_start = i + 1
                    func_name = m2.group(1) + " (constructor)"
                    break

        if func_start is None:
            return None, None, None

        # Step 2: Find method end by tracking brace { } balance
        brace_count = 0
        found_open_brace = False
        func_end = len(lines)  # fallback: end of file

        for i in range(func_start - 1, len(lines)):
            for ch in lines[i]:
                if ch == '{':
                    brace_count += 1
                    found_open_brace = True
                elif ch == '}':
                    brace_count -= 1

            # Once we've seen at least one { and balance returns to 0, we're done
            if found_open_brace and brace_count <= 0:
                func_end = i + 1  # exclusive (one past the closing brace line)
                break

        return func_start, func_end, func_name

    # ==========================================================
    # TOOL: SEARCH — Find pattern across repo
    # ==========================================================

    def _exec_search(self, params: Dict, repo_name: str) -> Dict[str, Any]:
        """
        SEARCH(pattern, max_matches)

        Grep all source files in the repo for a pattern.
        Returns filename, line_number, and preview for each match.

        Language-aware:
            python → searches *.py
            java   → searches *.java
        """
        pattern = params.get("pattern") or params.get("query")
        if not pattern:
            return {"error": "pattern is required"}

        # SEARCH cap + dedup (only for 9tool_searchcap)
        if self.ablation_config == "9tool_searchcap":
            cache_key = (repo_name, pattern.lower())
            if cache_key in self._search_cache:
                return self._search_cache[cache_key]
            if self._search_count >= 3:
                return {"error": "SEARCH limit reached (3 per issue). Classify with what you have."}

        max_matches = max(1, min(
            int(params.get("max_matches", self.limits.max_search_matches)),
            self.limits.max_search_matches,
        ))

        repo_path = (self.repos_dir / repo_name).resolve()
        if not repo_path.exists():
            return {"error": f"Repository not found: {repo_name}"}

        exclude_dirs = list(self._all_skip_dirs)

        if shutil.which("rg"):
            cmd = ["rg", "--no-heading", "--line-number", "--max-count",
                   str(max_matches), "--case-insensitive"]
            for g in self._glob_patterns:
                cmd.extend(["--glob", g])
            for d in exclude_dirs:
                cmd.extend(["--glob", f"!{d}/**"])
            cmd.extend(["--", pattern, str(repo_path)])
        else:
            include_args = []
            for g in self._glob_patterns:
                include_args.extend(["--include", g])
            exclude_args = []
            for d in exclude_dirs:
                exclude_args.extend(["--exclude-dir", d])
            cmd = ["grep", "-r", "-n", "-i", "-m", str(max_matches)] + \
                  include_args + exclude_args + ["--", pattern, str(repo_path)]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return {"error": f"Search failed: {e}"}

        matches: List[Dict[str, Any]] = []
        for line in result.stdout.splitlines():
            if len(matches) >= max_matches:
                break
            parts = line.split(":", 2)
            if len(parts) < 3 or not parts[1].isdigit():
                continue
            filepath, lineno, preview = parts[0], parts[1], parts[2]
            try:
                rel = str(Path(filepath).relative_to(repo_path))
            except ValueError:
                rel = filepath
            matches.append({
                "filename": rel,
                "line_number": int(lineno),
                "preview": preview.strip()[:200],
            })

        result = {
            "success": True,
            "pattern": pattern,
            "num_matches": len(matches),
            "matches": matches,
        }

        # Store in cache + increment counter (only for 9tool_searchcap)
        if self.ablation_config == "9tool_searchcap":
            cache_key = (repo_name, pattern.lower())
            self._search_cache[cache_key] = result
            self._search_count += 1

        return result

    # ==========================================================
    # TOOL: LIST_DIRECTORY — List files and directories
    # ==========================================================

    def _exec_list_directory(self, params: Dict, repo_name: str) -> Dict[str, Any]:
        """
        LIST_DIRECTORY(directory)

        List source files and subdirectories at a given path.
        Use "." for the repo root.

        Language-aware:
            python → lists .py files
            java   → lists .java files
        """
        directory = params.get("directory", ".")
        repo_path = self.repos_dir / repo_name

        if not repo_path.exists():
            return {"error": f"Repository not found: {repo_name}"}

        target = (repo_path / directory).resolve() if directory and directory != "." else repo_path.resolve()

        try:
            target.relative_to(repo_path.resolve())
        except ValueError:
            return {"error": "Access denied: directory outside repository boundaries"}

        if not target.exists():
            return {"error": f"Directory not found: {directory}"}

        try:
            dirs = []
            files = []
            for item in sorted(target.iterdir()):
                if item.name.startswith("."):
                    continue  # Skip hidden files/directories
                if item.is_dir():
                    # Skip noisy directories for the target language
                    if item.name in self._all_skip_dirs:
                        continue
                    dirs.append(item.name + "/")
                elif item.suffix in self._file_extensions:
                    files.append(item.name)

            return {
                "success": True,
                "directory": directory or ".",
                "directories": dirs,
                "source_files": files,
                # Keep backward compat key for existing code that reads "python_files"
                "python_files": files,
                "total_items": len(dirs) + len(files),
            }
        except Exception as e:
            return {"error": f"Failed to list directory: {e}"}

    # ==========================================================
    # Shared callgraph lookup (exact match → suffix match → dynamic)
    # ==========================================================

    def _find_callgraph_node(self, node: str, cg_repo: str,
                              current_cg: Optional[Dict] = None) -> Optional[Dict]:
        """
        Find a callgraph entry for `node` in `cg_repo`.

        Lookup order:
          1. Exact match on current issue's callgraph
          2. Exact match across all callgraphs for the same repo
          3. Suffix match (e.g. "get_hash" matches "RSAKey.get_hash")
        """
        if current_cg and node == current_cg.get("function_name"):
            return current_cg

        suffix = f".{node}"
        suffix_match = None

        for cg in self.call_graphs.values():
            if (cg.get("status") == "success"
                    and cg.get("repo_name") == cg_repo):
                fname = cg.get("function_name", "")
                if fname == node:
                    return cg
                if not suffix_match and fname.endswith(suffix):
                    suffix_match = cg

        if suffix_match:
            return suffix_match

        return None

    # ==========================================================
    # TOOL: GET_SUBGRAPH — Get call graph around a function
    # ==========================================================

    def _exec_get_subgraph(self, params: Dict, issue_id: str,
                           repo_name: str = "") -> Dict[str, Any]:
        """
        GET_SUBGRAPH(node, depth)

        Get the call graph (callers + callees) for a function.
        Checks pre-computed callgraphs.

        Args:
            node:  Function name (e.g., "validate_session")
            depth: 1 = direct callers/callees, 2 = two hops, max 3
        """
        node = params.get("node")
        if not node:
            return {"error": "node is required"}

        depth = params.get("depth", 1)
        if not isinstance(depth, int) or depth < 1:
            return {"error": "depth must be a positive integer"}
        if depth > 3:
            return {"error": "Maximum depth is 3"}

        # Get the call graph for the current issue from pre-computed data
        current_cg = self.call_graphs.get(issue_id)

        if current_cg:
            cg_repo = current_cg.get("repo_name", "")
        else:
            cg_repo = repo_name

        # --- Find call graph for the requested node ---
        target_cg = self._find_callgraph_node(node, cg_repo, current_cg)

        if not target_cg:
            return {
                "error": f"No call graph found for node '{node}' in repo '{cg_repo}'",
                "suggestion": (
                    f"Call graph unavailable for '{node}'. "
                    f"Use SEARCH(pattern=\"{node}\") to find where this function is defined and called."
                ),
            }

        ctx = target_cg.get("call_graph_context", {})
        callers = ctx.get("callers", [])
        callees = ctx.get("callees", [])

        # --- Multi-hop expansion for depth >= 2 ---
        if depth >= 2:
            # Build lookup: function_name → call_graph_context (same repo only)
            func_to_graph = {
                cg.get("function_name", ""): cg.get("call_graph_context", {})
                for cg in self.call_graphs.values()
                if cg.get("repo_name") == repo_name and cg.get("status") == "success"
            }

            # Expand callees (follow one more hop)
            depth2_callees = set(callees)
            for callee in callees:
                if callee in func_to_graph:
                    depth2_callees.update(func_to_graph[callee].get("callees", []))

            # Expand callers (follow one more hop)
            depth2_callers = set(callers)
            for caller in callers:
                if caller in func_to_graph:
                    depth2_callers.update(func_to_graph[caller].get("callers", []))

            callees = list(depth2_callees)
            callers = list(depth2_callers)

        return {
            "success": True,
            "node": node,
            "depth": depth,
            "callers": callers[:50],
            "callees": callees[:50],
            "num_callers": len(callers),
            "num_callees": len(callees),
        }

    # ==========================================================
    # TOOL: GET_PREDECESSOR — Get callers of a function
    # ==========================================================

    def _exec_get_predecessor(self, params: Dict, issue_id: str,
                              repo_name: str = "") -> Dict[str, Any]:
        """
        GET_PREDECESSOR(node)

        Get all functions that call a specific function.
        Simpler than GET_SUBGRAPH — only returns callers, no depth expansion.
        Checks pre-computed callgraphs first, then falls back to dynamic.
        """
        node = params.get("node")
        if not node:
            return {"error": "node is required"}

        current_cg = self.call_graphs.get(issue_id)

        if current_cg:
            cg_repo = current_cg.get("repo_name", "")
        else:
            cg_repo = repo_name

        target_cg = self._find_callgraph_node(node, cg_repo, current_cg)

        if not target_cg:
            return {
                "error": f"No call graph found for node '{node}' in repo '{cg_repo}'",
                "suggestion": (
                    f"Call graph unavailable for '{node}'. "
                    f"Use SEARCH(pattern=\"{node}\") to find where this function is defined and called."
                ),
            }

        callers = target_cg.get("call_graph_context", {}).get("callers", [])

        return {
            "success": True,
            "node": node,
            "callers": callers,
            "num_callers": len(callers),
        }

    # ==========================================================
    # RUN_SEMGREP — Run Semgrep on the repo
    # ==========================================================
    # LLM can ask to run Semgrep with crypto rules, general rules,
    #  or even provide its own YAML rule."
    # "LLM gives you a bash command. You run that command, redirect
    #  output to a file, read that file and give it back to the LLM."

    def _exec_run_semgrep(self, params: Dict, repo_name: str) -> Dict[str, Any]:
        """
        RUN_SEMGREP(mode, custom_rule)

        Run Semgrep on the repository.

        Language-aware:
            python → crypto mode uses 19 targeted rule dirs (weak hash, cipher,
                     SSL/TLS, insecure transport, key size, JWT, Django/Flask
                     secret leakage, insecure UUID, hardcoded AWS tokens, etc.)
            java   → crypto mode uses 10 targeted rule dirs (DES, 3DES, ECB,
                     Blowfish, RC2, RC4, MD5, SHA1, weak RSA, weak SSL,
                     static IV, CBC padding oracle, JWT, insecure SMTP, etc.)

        Modes:
            "crypto"  — Run crypto-specific rules for the target language
            "general" — Run all default rules (auto config)
            "custom"  — Run with LLM-provided YAML rule (pass in custom_rule param)

        Returns:
            {"success": True, "output": "...", "exit_code": 0}
        """
        mode = params.get("mode", "crypto")
        custom_rule = params.get("custom_rule")

        repo_path = self.repos_dir / repo_name
        if not repo_path.exists():
            return {"error": f"Repository not found: {repo_name}"}

        # Track temp files for cleanup
        tmp_file_path = None

        # --- Build semgrep command based on mode ---
        if mode == "crypto":
            crypto_configs = _LANG_SEMGREP_CRYPTO.get(self.language, ["p/security-audit"])
            cmd = ["semgrep"]
            for cfg in crypto_configs:
                cmd.extend(["--config", cfg])
            cmd.extend(["--json", str(repo_path)])
        elif mode == "general":
            cmd = ["semgrep", "--config", "auto", "--json", str(repo_path)]
        elif mode == "custom" and custom_rule:
            # Write the LLM's custom YAML rule to a temp file, then run it
            try:
                tmp = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".yaml", delete=False
                )
                tmp.write(custom_rule)
                tmp.close()
                tmp_file_path = tmp.name  # save path for cleanup
                cmd = ["semgrep", "--config", tmp.name, "--json", str(repo_path)]
            except Exception as e:
                return {"error": f"Failed to write custom rule: {e}"}
        else:
            return {
                "error": (
                    "Invalid mode. Use 'crypto', 'general', or 'custom' "
                    "(with custom_rule parameter containing YAML)."
                )
            }

        # --- Execute semgrep ---
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2-minute timeout
            )

            output = result.stdout or result.stderr
            # Truncate very long output (Semgrep can be verbose)
            if len(output) > 50_000:
                output = output[:50_000] + "\n... [truncated at 50KB]"

            return {
                "success": True,
                "tool": "semgrep",
                "mode": mode,
                "output": output,
                "exit_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"error": "Semgrep timed out (120s limit)"}
        except FileNotFoundError:
            return {"error": "Semgrep not installed. Install with: pip install semgrep"}
        except Exception as e:
            return {"error": f"Error running Semgrep: {e}"}
        finally:
            # Clean up temp file for custom mode
            if tmp_file_path and os.path.exists(tmp_file_path):
                try:
                    os.unlink(tmp_file_path)
                except OSError:
                    pass  # best effort cleanup

    # ==========================================================
    # NEW TOOL: RUN_CODEQL — Run CodeQL on the repo
    # ==========================================================

    def _exec_run_codeql(self, params: Dict, repo_name: str) -> Dict[str, Any]:
        """
        RUN_CODEQL(mode, custom_query)

        Run CodeQL analysis on the repository.

        Language-aware:
            python → uses python-security-and-quality / python-security-extended
            java   → uses java-security-and-quality / java-security-extended

        PREREQUISITE: A CodeQL database must exist for the repo.
        CodeQL databases are heavy to create (can take minutes), so they
        should be pre-built. This tool checks for an existing database.

        Modes:
            "crypto"  — Run crypto/security-specific query suite for the language
            "general" — Run extended security query suite for the language
            "custom"  — Run LLM-provided .ql query file

        Database location: config.paths.codeql_dbs_dir/{repo_name}/
        """
        mode = params.get("mode", "crypto")
        custom_query = params.get("custom_query")

        repo_path = self.repos_dir / repo_name
        if not repo_path.exists():
            return {"error": f"Repository not found: {repo_name}"}

        # Check for pre-built CodeQL database.
        # Try both {repo_name} and {repo_name}-db (cluster databases use the -db suffix).
        codeql_lang = _LANG_CODEQL_LANG.get(self.language, "python")
        db_path = self.config.paths.codeql_dbs_dir / repo_name
        if not db_path.exists():
            db_path_alt = self.config.paths.codeql_dbs_dir / f"{repo_name}-db"
            if db_path_alt.exists():
                db_path = db_path_alt

        if not db_path.exists():
            return {
                "error": (
                    f"CodeQL database not found at {db_path}. "
                    f"Create it first with: codeql database create {db_path} "
                    f"--language={codeql_lang} --source-root={repo_path}"
                ),
                "suggestion": "Pre-build CodeQL databases before running analysis",
            }

        # Track temp files for cleanup (custom query file + output SARIF file)
        tmp_query_path = None
        tmp_output_path = None

        # Create temp file for CodeQL output (replaces fragile --output=/dev/stdout)
        try:
            tmp_out = tempfile.NamedTemporaryFile(
                mode="w", suffix=".sarif", delete=False
            )
            tmp_out.close()
            tmp_output_path = tmp_out.name
        except Exception as e:
            return {"error": f"Failed to create temp output file: {e}"}

        # --- Build codeql command based on mode ---
        if mode == "crypto":
            # Language-specific crypto/security query suite
            query_suite = _LANG_CODEQL_CRYPTO.get(self.language, "python-security-and-quality")
            cmd = [
                "codeql", "database", "analyze", str(db_path),
                query_suite,
                "--format=sarif-latest",
                f"--output={tmp_output_path}",
            ]
        elif mode == "general":
            # Language-specific general security query suite
            query_suite = _LANG_CODEQL_GENERAL.get(self.language, "python-security-extended")
            cmd = [
                "codeql", "database", "analyze", str(db_path),
                query_suite,
                "--format=sarif-latest",
                f"--output={tmp_output_path}",
            ]
        elif mode == "custom" and custom_query:
            # Write LLM's custom .ql query to a temp file
            try:
                tmp_q = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".ql", delete=False
                )
                tmp_q.write(custom_query)
                tmp_q.close()
                tmp_query_path = tmp_q.name  # save for cleanup
                cmd = [
                    "codeql", "database", "analyze", str(db_path),
                    tmp_query_path,
                    "--format=sarif-latest",
                    f"--output={tmp_output_path}",
                ]
            except Exception as e:
                # Clean up output temp file before returning
                if tmp_output_path and os.path.exists(tmp_output_path):
                    os.unlink(tmp_output_path)
                return {"error": f"Failed to write custom query: {e}"}
        else:
            # Clean up output temp file before returning
            if tmp_output_path and os.path.exists(tmp_output_path):
                os.unlink(tmp_output_path)
            return {
                "error": (
                    "Invalid mode. Use 'crypto', 'general', or 'custom' "
                    "(with custom_query parameter containing QL code)."
                )
            }

        # --- Execute CodeQL ---
        try:
            # Ensure CodeQL binary is findable even if not in shell PATH.
            # Check common install locations and prepend to env PATH.
            _codeql_env = os.environ.copy()
            for _codeql_candidate in ["/usr/local/codeql", "/opt/codeql"]:
                if os.path.isfile(os.path.join(_codeql_candidate, "codeql")):
                    _codeql_env["PATH"] = _codeql_candidate + ":" + _codeql_env.get("PATH", "")
                    break
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5-minute timeout (CodeQL is slow)
                env=_codeql_env,
            )

            # Read output from temp file (more reliable than stdout piping)
            output = ""
            if tmp_output_path and os.path.exists(tmp_output_path):
                try:
                    with open(tmp_output_path, "r", encoding="utf-8") as f:
                        output = f.read()
                except Exception:
                    pass

            # Fall back to stdout/stderr if temp file was empty
            if not output:
                output = result.stdout or result.stderr or ""

            # Detect fatal errors even when exit code is ambiguous
            _fatal_phrases = (
                "cannot be found",
                "fatal error",
                "A fatal error occurred",
                "No database found",
                "Error: Could not",
            )
            is_fatal = result.returncode != 0 or any(
                p.lower() in output.lower() for p in _fatal_phrases
            )

            if is_fatal:
                return {
                    "error": f"CodeQL failed (exit {result.returncode}): {output[:500]}",
                    "suggestion": (
                        "Install query packs with: "
                        "codeql pack download codeql/python-queries codeql/java-queries"
                    ),
                }

            if len(output) > 50_000:
                output = output[:50_000] + "\n... [truncated at 50KB]"

            return {
                "success": True,
                "tool": "codeql",
                "mode": mode,
                "output": output,
                "exit_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"error": "CodeQL timed out (300s limit)"}
        except FileNotFoundError:
            return {"error": "CodeQL not installed. See: https://codeql.github.com/"}
        except Exception as e:
            return {"error": f"Error running CodeQL: {e}"}
        finally:
            # Clean up ALL temp files (query + output)
            for tmp_path in (tmp_query_path, tmp_output_path):
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass  # best effort cleanup

