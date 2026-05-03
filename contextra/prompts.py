"""
prompts.py — Prompt Templates and Formatting
==============================================

All prompt construction logic lives here.
Nothing about LLM calling or tool execution — just string building.

The prompt is built from the FP Identifier v2 template
(fp_identifier_prompt_v2.md). Tool definitions are passed separately
via the native tools= API parameter.

The prompt focuses on:
  - DJB/MG persona and verification approach (3a-3e)
  - Alert context (code, alert ID/text, repo structure)
  - 3 classification examples (TP, FP, NON_ACTIONABLE)
  - 9 investigation tools with examples
  - No KB dependency — DJB knows what to do

Contents:
    build_llm_prompt()              — Main prompt (v2 template) with issue context
    format_tool_result_content()    — Format tool result for native tool history
    format_list()                   — Format list for display
"""

from __future__ import annotations

from typing import Any, Dict, List

from config import SystemConfig


# =====================================================
# MAIN PROMPT BUILDER (v2 template)
# =====================================================

def build_llm_prompt(
    context: Dict[str, Any],
    config: SystemConfig,
    ablation_config: str = "9tool",
) -> str:
    """
    Build the LLM prompt for classifying a crypto misuse alert.

    Uses the FP Identifier v2 template:
      - DJB/MG persona (25-year theoretical cryptographer)
      - 5-step verification approach (3a-3e)
      - Alert context from CSV + repo files (no KB)
      - 3 classification examples (TP, FP, NON_ACTIONABLE)
      - 9 investigation tools with examples

    This prompt is sent as the user message on the first iteration.
    Tool definitions are NOT included here — they are passed separately
    via the native tools= API parameter.
    """
    language = config.language

    # --- Alert fields (from CSV or detection engine) ---
    tool_issue_id = context.get("tool_issue_id", "")
    alert_text = context.get("alert_text", "")
    alert_location = context.get("issue_location", "unknown")

    # Build the alert line: "B303 — alert text" for SAST, just "alert text" for detection engine
    alert_line = f"{tool_issue_id} — {alert_text}" if tool_issue_id else alert_text
    repo_name = context.get("repo_name", "unknown")
    rel_filename = context.get("rel_filename", "unknown")

    # --- Code snippet (from repo files) ---
    code_snippet = context.get("code_snippet", "[No code available]")

    # --- README and folder structure (from repo files) ---
    readme_raw = context.get("readme") or ""
    readme_text = readme_raw[:1000] + "..." if len(readme_raw) > 1000 else (readme_raw or "[None]")
    structure_raw = context.get("folder_structure") or ""
    structure_text = structure_raw[:500] + "..." if len(structure_raw) > 500 else (structure_raw or "[None]")

    # --- Build tool descriptions based on ablation config ---
    ablation = getattr(config, "ablation_config", ablation_config)

    _SEARCH_DESC = f"""**1. SEARCH(pattern: String, max_matches: Integer)** — Grep all source files for a pattern. Supports regex, case-insensitive. Returns file, line number, and line preview for each match. Use to find where the flagged function or variable is used elsewhere in the codebase. SEARCH is case-insensitive — do not repeat a query with different capitalization. If a search returns 0 matches, that information is absent from the codebase — classify based on what you found, not on what you couldn't find.

Examples:
  Find where the flagged function's return value is consumed:
  ```json
  {{"name": "SEARCH", "arguments": {{"pattern": "generate_signature"}}}}
  ```

  Check if verify=False is gated by a debug flag:
  ```json
  {{"name": "SEARCH", "arguments": {{"pattern": "insecure|no.verify|debug"}}}}
  ```

  Search for protocol or spec references that might justify the algorithm:
  ```json
  {{"name": "SEARCH", "arguments": {{"pattern": "RFC|protocol|spec|mandatory|required by"}}}}
  ```

---"""

    _GET_DESC = f"""**2. GET(filename: String, line_start: Integer, line_end: Integer)** — Read specific lines from a file. Lines are 1-indexed. Use to read the code surrounding the flagged line and understand the immediate context — what happens before and after the flagged crypto operation.

Examples:
  Read code around the flagged location:
  ```json
  {{"name": "GET", "arguments": {{"filename": "api/client.py", "line_start": 70, "line_end": 90}}}}
  ```

  Read the first 30 lines of a file (imports and module-level setup):
  ```json
  {{"name": "GET", "arguments": {{"filename": "config.py", "line_start": 1, "line_end": 30}}}}
  ```

---"""

    _GET_FUNCTION_DESC = f"""**3. GET_FUNCTION(filename: String, line_number: Integer)** — Get the complete function/method body containing a given line. Returns the full function definition with line numbers. Use to see the full function where the flagged crypto operation occurs — what parameters it takes, what it returns, and how the crypto output is used within the function.

Example:
  Get the function containing the flagged line:
  ```json
  {{"name": "GET_FUNCTION", "arguments": {{"filename": "auth/tokens.py", "line_number": 42}}}}
  ```

---"""

    _GET_FILE_DESC = f"""**4. GET_FILE(filename: String)** — Read entire file contents (max 100KB). Note that the output will be truncated to only the first 100KB when the file size is larger than 100KB. Use to read requirements files (to check which crypto library version is installed) or small configuration files.

Examples:
  Read the requirements file:
  ```json
  {{"name": "GET_FILE", "arguments": {{"filename": "requirements.txt"}}}}
  ```

  Read a configuration module:
  ```json
  {{"name": "GET_FILE", "arguments": {{"filename": "settings.py"}}}}
  ```

---"""

    _LIST_DIR_DESC = f"""**5. LIST_DIRECTORY(directory: String)** — List source files and subdirectories at a path. Use "." for the repo root. Use to understand the project structure and determine whether the flagged file is in a test, example, or vendored directory.

Examples:
  List the repo root:
  ```json
  {{"name": "LIST_DIRECTORY", "arguments": {{"directory": "."}}}}
  ```

  List a subdirectory:
  ```json
  {{"name": "LIST_DIRECTORY", "arguments": {{"directory": "src/crypto"}}}}
  ```

---"""

    _SUBGRAPH_DESC = f"""**6. GET_SUBGRAPH(node: String, depth: Integer)** — Get call graph around a function — both who calls it (callers) and what it calls (callees). Useful for tracing data flow. Use to trace data flow: does the flagged crypto output reach network-facing code, database writes, or authentication logic?

Example:
  Get callers and callees of encrypt_data, 2 hops deep:
  ```json
  {{"name": "GET_SUBGRAPH", "arguments": {{"node": "encrypt_data", "depth": 2}}}}
  ```

---"""

    _PREDECESSOR_DESC = f"""**7. GET_PREDECESSOR(node: String)** — Get all functions that call a specific function (callers only). Simpler than GET_SUBGRAPH when you only need callers. Use to determine who calls the flagged function and whether the callers are security-critical or benign.

Example:
  Find all callers of generate_token:
  ```json
  {{"name": "GET_PREDECESSOR", "arguments": {{"node": "generate_token"}}}}
  ```

---"""

    _SEMGREP_DESC = f"""**8. RUN_SEMGREP(mode: Enum "crypto"|"general"|"custom", custom_rule: String)** — Run Semgrep pattern-based static analysis on the entire repository. Semgrep matches AST patterns but does not perform inter-procedural data-flow analysis. Use to gather additional evidence about crypto usage patterns across the codebase. Semgrep findings are evidence, not conclusions — always read the actual code for any finding before using it to support your classification.

Modes:
- "crypto": Runs targeted crypto-security rules covering hashlib, ssl, PyCryptodome, python-cryptography, JWT, requests, Django, Flask, and boto3. For crypto libraries not covered (e.g. PyNaCl, pyOpenSSL, M2Crypto, paramiko), use "custom" mode with your own rule.
- "general": Runs all default security rules (broader scan including non-crypto issues).
- "custom": Provide your own Semgrep YAML rule via the custom_rule parameter.

Examples:
  Run crypto-focused scan:
  ```json
  {{"name": "RUN_SEMGREP", "arguments": {{"mode": "crypto"}}}}
  ```

  Run a custom rule to find specific patterns:
  ```json
  {{"name": "RUN_SEMGREP", "arguments": {{"mode": "custom", "custom_rule": "rules:\\n  - id: ecdsa-keygen\\n    pattern: ecdsa.SigningKey.generate(...)\\n    message: Check curve parameter\\n    severity: WARNING\\n    languages: [{language}]"}}}}
  ```

---"""

    _CODEQL_DESC = f"""**9. RUN_CODEQL(mode: Enum "crypto"|"general"|"custom", custom_query: String)** — Run CodeQL data-flow static analysis on the entire repository. CodeQL performs inter-procedural data-flow analysis — it can trace whether the flagged crypto output flows to a sensitive sink across function boundaries. CodeQL findings are evidence, not conclusions — always read the actual code for any finding before using it to support your classification.

Modes:
- "crypto": Runs `{language}-security-and-quality` query suite — crypto and security issues with data-flow tracking.
- "general": Runs `{language}-security-extended` query suite — all security issues with data-flow tracking.
- "custom": Provide your own QL query via the custom_query parameter.

Examples:
  Run crypto-focused data-flow analysis:
  ```json
  {{"name": "RUN_CODEQL", "arguments": {{"mode": "crypto"}}}}
  ```

  Run general security analysis:
  ```json
  {{"name": "RUN_CODEQL", "arguments": {{"mode": "general"}}}}
  ```

---"""

    # Assemble tool descriptions based on config
    tool_descs = []
    if ablation not in ("6tool",):
        tool_descs.append(_SEARCH_DESC)
        tool_descs.append(_GET_DESC)
        tool_descs.append(_GET_FUNCTION_DESC)
    tool_descs.append(_GET_FILE_DESC)
    tool_descs.append(_LIST_DIR_DESC)
    tool_descs.append(_SUBGRAPH_DESC)
    tool_descs.append(_PREDECESSOR_DESC)
    if ablation != "7tool_nosast":
        tool_descs.append(_SEMGREP_DESC)
        tool_descs.append(_CODEQL_DESC)

    tool_descriptions = "\n".join(tool_descs)

    # For 8tool: include GET + GET_FUNCTION but not SEARCH
    if ablation == "8tool":
        tool_descs_8 = []
        tool_descs_8.append(_GET_DESC)
        tool_descs_8.append(_GET_FUNCTION_DESC)
        tool_descs_8.append(_GET_FILE_DESC)
        tool_descs_8.append(_LIST_DIR_DESC)
        tool_descs_8.append(_SUBGRAPH_DESC)
        tool_descs_8.append(_PREDECESSOR_DESC)
        tool_descs_8.append(_SEMGREP_DESC)
        tool_descs_8.append(_CODEQL_DESC)
        tool_descriptions = "\n".join(tool_descs_8)

    # --- Build the v2 prompt ---
    prompt = f"""You are a theoretical cryptographer with more than 25 years of real crypto engineering experience under your belt (similar to Daniel J. Bernstein (DJB) and Matthew Green (MG) of Johns Hopkins University). You have been given a cryptographic security alert while scanning a {language} application repository. Your task is to independently investigate the flagged code and classify the alert as TP (True Positive), FP (False Positive), or NON_ACTIONABLE.

- **TP** (True Positive): The flagged code is a genuine cryptographic misuse that poses a real security risk and should be fixed.
- **FP** (False Positive): The alert is incorrect — the flagged code is not a real security issue.
- **NON_ACTIONABLE**: The flagged code is a real cryptographic weakness, but the developer cannot fix it without breaking functionality (e.g., a protocol or specification mandates the insecure algorithm).

**Potential DJB-/MG-like Verification Approach:**
The following is a potential approach a human auditor like DJB or Matthew Green may use to verify a cryptographic alert. The following is just a suggestion. You're free to use your own judgment, too. For some of the steps you can use tools, the description of which is in the next section.

1. Read the flagged code and understand what cryptographic operation is being performed.
2. Trace the data flow: does the crypto output go over the network, into a database, or into authentication/session logic? Or does it stay internal (caching, logging, dedup)? Generally, internal use of an insecure cryptographic primitive may be acceptable if it does not leak externally.
3. Determine whether the issue is actionable by considering the following:

     a. **Test or example code**: Is the code in a test file, tutorial, or API usage example? If yes, classify as FP.

     b. **Third-party or vendored library**: Is the code in a third-party library checked into the repo, not the application's own code? Look for signs like: files under `vendor/`, `third_party/`, `lib/`; copyright headers from other organizations; code that matches a known open-source package listed in requirements.txt. If yes, classify as FP.

     c. **CLI or debug mode**: Is the insecure behavior controlled by a CLI flag or configuration option (e.g., `--insecure`, `--no-verify`, `verify=False` gated by a debug flag)? If the developer provides an option to disable security for debugging or local development, classify as FP.

     d. **Stronger wrapper**: Is the weak primitive wrapped inside a stronger cryptographic construction (e.g., MD5 used inside HMAC-SHA256, or a weak hash used only as input to a KDF)? If the security depends on the outer construction and not on the inner primitive's collision resistance, classify as FP.

     e. **Protocol mandate**: Is the developer bound by a protocol, service, or spec requirement that mandates the insecure algorithm? If so, verify the mandate by looking for spec references, RFC numbers, protocol documentation, or code comments. If confirmed, classify as NON_ACTIONABLE.

4. If none of the above apply and the weak primitive is used for a security-critical operation, classify as TP.

**The following information is provided for each alert you review:**
- **Alert ID**: The rule or issue identifier (e.g., B303, DUO130)
- **Location**: File path and line number
- **Repository**: The repository name
- **Alert text**: The original alert message or description of the issue
- **Code**: The source code at and around the flagged line
- **README**: First ~1000 characters of the project README (if available)
- **Structure**: Top-level directory listing of the repository

---

**Alert Under Review:**
- Alert: {alert_line}
- Location: {alert_location}
- Repository: {repo_name}
- File: `{rel_filename}`

**Code at the flagged location:**
```{language}
{code_snippet}
```

**Repository Context:**
README: {readme_text}
Structure: {structure_text}

---

**Available Tools and Tool Calling Convention:**

# Tools are invoked via native API tool calling. Each tool call is a JSON object with the tool name and its arguments.

---

{tool_descriptions}

**Classification Examples:**

*Example 1 — TP:*
Alert flags `hashlib.md5(password.encode()).hexdigest()` in `auth/login.py`.
The function `verify_password()` compares this hash against stored hashes for user login.
→ **TP**: MD5 is used to hash passwords for authentication. MD5 is broken for this purpose — use bcrypt/argon2.

*Example 2 — FP:*
Alert flags `hashlib.sha1(file_content).hexdigest()` in `utils/cache.py`.
The return value is used as a cache key in a dictionary. No security decisions depend on it.
→ **FP**: SHA1 used for cache key generation, not security. Collisions would cause a cache miss, not a vulnerability.

*Example 3 — NON_ACTIONABLE:*
Alert flags `SHA1` in `crypto/bitcoin.py`.
Code comments reference BIP-32 specification. The Bitcoin protocol mandates SHA1 in its key derivation.
→ **NON_ACTIONABLE**: SHA1 is required by the Bitcoin protocol specification. Changing it would break compatibility.

---

**Output Format (JSON only, no other text):**

```json
{{"classification": "TP|FP|NON_ACTIONABLE", "reasoning": "Concise explanation — what the crypto does, where its output goes, and why it is or is not a real issue."}}
```"""

    return prompt


# =====================================================
# TOOL RESULT FORMATTING (for native tool history)
# =====================================================

def format_tool_result_content(
    command: str,
    result: Dict[str, Any],
    ablation_config: str = "9tool",
) -> str:
    """
    Format a tool result as plain text content for native tool history.

    With native tool calling, tool results are sent via the API's tool
    result mechanism (role="tool" for OpenAI, tool_result for Claude).
    The protocol itself tells the model it can make another tool call
    or respond with text — no extra guidance needed.
    """
    if "error" in result:
        msg = f"ERROR: {result['error']}"
        if result.get("suggestion"):
            msg += f"\nSUGGESTION: {result['suggestion']}"
        return msg

    if command in {"GET", "GET_FILE", "GET_FUNCTION"}:
        content = result.get("content") or ""
        if ablation_config == "6tool" and command == "GET_FILE":
            return content
        return content[:1500]

    if command == "SEARCH":
        rows = result.get("matches", [])[:20]
        return (
            "\n".join(f"{m['filename']}:{m['line_number']}  {m['preview']}" for m in rows)
            or "[no matches]"
        )

    if command == "LIST_DIRECTORY":
        dirs = result.get("directories", [])
        files = result.get("source_files", result.get("python_files", []))
        parts = []
        if dirs:
            parts.append("Directories:\n" + "\n".join(dirs))
        if files:
            parts.append("Source files:\n" + "\n".join(files))
        return "\n\n".join(parts) if parts else "[empty directory]"

    if command == "GET_SUBGRAPH":
        callers = result.get("callers", [])[:20]
        callees = result.get("callees", [])[:20]
        return "Callers:\n" + "\n".join(callers) + "\n\nCallees:\n" + "\n".join(callees)

    if command == "GET_PREDECESSOR":
        callers = result.get("callers", [])[:30]
        return "Callers:\n" + "\n".join(callers)

    if command in {"RUN_SEMGREP", "RUN_CODEQL"}:
        output = result.get("output", "")
        return output[:3000] if len(output) > 3000 else output

    return str(result)[:1000]


# =====================================================
# HELPERS
# =====================================================

def format_list(items: List[str], empty_msg: str = "None") -> str:
    """Format a list for display. Shows first 5, with '+ N more' if truncated."""
    if not items:
        return empty_msg
    shown = ", ".join(items[:5])
    if len(items) > 5:
        shown += f" ... ({len(items) - 5} more)"
    return shown
