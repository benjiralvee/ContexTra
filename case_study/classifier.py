"""
classifier.py — Agentic Classification Loop
=============================================

The core logic: given an issue, build context, then iteratively
query the LLM and execute tools until it classifies the issue.

Two modes:
    "stateless"     — Rebuild full message list every iteration
    "conversation"  — Send full prompt once, then only send tool results

All providers (Claude, GPT, Ollama) use native tool calling for
investigation tools (SEARCH, GET, etc.). Classification is via
text response — OpenAI/Ollama use response_format=json_object to
guarantee valid JSON output.

The result dict format is consistent across all configurations
so existing chart/analysis scripts work without changes.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from config import SystemConfig
from llm_interface import LLMClient, get_tool_definitions
from tools import ToolExecutor
from prompts import (
    build_llm_prompt,
    format_tool_result_content,
)


class AgenticClassifier:
    """
    Classifies crypto misuse issues using an agentic LLM loop.

    Flow:
        1. build_initial_context() — gather all info about the issue
        2. Build prompt (prompts.py) — issue context, guidance, few-shot
        3. Send to LLM with native tools (llm_interface.py)
        4. Parse response:
           - If text with classification JSON → done, return result
           - If investigation tool called → execute (tools.py) → send result → loop
        5. Repeat until classification or max_iterations
    """

    VALID_TOOLS = {
        "GET", "GET_FILE", "GET_FUNCTION", "SEARCH",
        "LIST_DIRECTORY", "GET_SUBGRAPH", "GET_PREDECESSOR",
        "RUN_SEMGREP", "RUN_CODEQL",
        "WEB_SEARCH", "CHECK_PACKAGE_STATUS",
        # "WGET",  # disabled Apr 2026: WEB_SEARCH replaces it
    }

    # Gate C: alert-text + code-snippet patterns for known-deprecated primitives.
    # MUST NOT include SHA-256, SHA-512, AES-CBC, AES-GCM, or any non-deprecated primitive.
    # Matched case-insensitively against alert_text + code_snippet + tool_issue_id ONLY
    # (not README, not folder_structure, not tool results) to avoid false positives.
    _GATE_C_PATTERNS: List[tuple] = [
        (r'\bMD5\b',                             'MD5'),
        (r'\bSHA[-_]?1\b',                       'SHA-1'),
        (r'\b(?:3DES|TripleDES|DESede)\b',       '3DES/TripleDES'),
        (r'\bDES\b',                             'DES'),
        (r'\bRC4\b',                             'RC4'),
        (r'\bRC2\b',                             'RC2'),
        (r'\bPBEWith(?:MD5|SHA1)\b',             'PBEWithMD5/SHA1'),
        (r'\bTLS[vV]?1[._]?[01]\b',             'TLSv1.0/TLSv1.1'),
        (r'\bSSL[vV]?[23]\b',                   'SSLv2/SSLv3'),
        (r'\bDUO133\b',                          'DUO133'),
        (r'\bpycrypto\b(?!dome)',                'pycrypto (abandoned)'),
    ]

    # Per-alert budgets for tools that hit external systems.
    # WEB_SEARCH goes over the network — cap to keep one alert from
    # monopolising iterations. CHECK_PACKAGE_STATUS is a PyPI call but
    # capped so the model doesn't loop on the same package.
    MAX_WEB_SEARCH_PER_ALERT = 5
    MAX_WGET_PER_ALERT = 5  # retained for revert; WGET currently disabled
    MAX_CHECK_PACKAGE_PER_ALERT = 10

    def __init__(
        self,
        config: SystemConfig,
        llm: LLMClient,
        tools: ToolExecutor,
        issues: Dict[str, Dict],
        call_graphs: Dict[str, Dict],
    ):
        self.config = config
        self.llm = llm
        self.tools = tools
        self.issues = issues
        self.call_graphs = call_graphs

        self._tool_definitions = get_tool_definitions()
        print(f"  Native tool calling: {len(self._tool_definitions)} investigation tools")
        print(f"  Classification via JSON text response")

    # ==========================================================
    # CONTEXT BUILDING
    # ==========================================================

    def build_initial_context(self, issue_id: str) -> Dict[str, Any]:
        """Build the initial context dict for an issue."""
        if issue_id not in self.issues:
            raise KeyError(f"Issue ID {issue_id} not found")

        issue = self.issues[issue_id]
        repo_name = issue.get("repo_name", "")
        filename = issue.get("filename", "")
        line_number = int(issue.get("line_number", 1))

        tool_issue_id = issue.get("tool_issue_id", "")
        source_tool = issue.get("source", "Unknown")
        all_sources = issue.get("all_sources", source_tool)

        rel_filename = self.tools.normalize_filename(filename, repo_name)

        code_snippet = self._read_code_snippet(
            repo_name, rel_filename, line_number,
            self.config.tool_limits.context_lines,
        )

        readme = self._load_readme(repo_name)
        folder_structure = self._get_folder_structure(repo_name)

        return {
            "issue_id": issue_id,
            "issue_location": f"{filename}:{line_number}",
            "repo_name": repo_name,
            "filename": filename,
            "rel_filename": rel_filename,
            "line_number": line_number,
            "tool": source_tool,
            "all_sources": all_sources,
            "tool_issue_id": tool_issue_id,
            "severity": issue.get("severity", ""),
            "cwe": issue.get("cwe", ""),
            "alert_text": issue.get("issue_text", ""),
            "code_snippet": code_snippet,
            "readme": readme,
            "folder_structure": folder_structure,
        }

    def _read_code_snippet(
        self, repo_name: str, rel_filename: str,
        line_number: int, context_lines: int,
    ) -> str:
        if not repo_name:
            return "[Missing repo_name]"

        file_path = self.tools.resolve_file_path(rel_filename, repo_name)
        if not file_path.exists():
            return f"[File not found: {repo_name}/{rel_filename}]"

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)

            return "\n".join(
                f"{i+1:4d}{' >>> ' if i+1 == line_number else '     '}{lines[i].rstrip()}"
                for i in range(start, end)
            )
        except Exception as e:
            return f"[Error reading file: {e}]"

    def _load_readme(self, repo_name: str) -> Optional[str]:
        repo_path = self.config.paths.repos_dir / repo_name
        if not repo_path.exists():
            return None

        for name in ("README.md", "README.rst", "README.txt", "README"):
            readme_path = repo_path / name
            if readme_path.exists():
                try:
                    content = readme_path.read_text(encoding="utf-8", errors="ignore")
                    return content[:5000] + "\n... [truncated]" if len(content) > 5000 else content
                except Exception:
                    pass
        return None

    def _get_folder_structure(self, repo_name: str) -> str:
        repo_path = self.config.paths.repos_dir / repo_name
        if not repo_path.exists():
            return "[Repository not found]"

        try:
            items = []
            for item in sorted(repo_path.iterdir()):
                if item.is_dir() and not item.name.startswith("."):
                    items.append(f"  {item.name}/")
                elif item.suffix in (".py" if self.config.language == "python" else ".java",):
                    items.append(f"  {item.name}")
            return "\n".join(items[:20])
        except Exception as e:
            return f"[Error: {e}]"

    # ==========================================================
    # MAIN CLASSIFICATION ENTRY POINT
    # ==========================================================

    def classify_issue(self, issue_id: str) -> Dict[str, Any]:
        # Fresh connection per alert — closes the previous HTTP client and
        # opens a new one so each alert gets an independent TCP session.
        self.llm = LLMClient(self.config.llm)
        print(f"  [connection] New LLMClient id={id(self.llm)} for issue #{issue_id}")

        print(f"\n{'='*60}")
        print(f"Classifying Issue #{issue_id} (mode: {self.config.mode})")
        print(f"{'='*60}")

        try:
            context = self.build_initial_context(issue_id)
        except Exception as e:
            return {
                "issue_id": issue_id,
                "classification": "ERROR",
                "reasoning": f"Failed to build context: {e}",
                "num_iterations": 0,
                "success": False,
            }

        if self.config.mode == "conversation":
            return self._classify_conversation(issue_id, context)
        else:
            return self._classify_stateless(issue_id, context)

    def classify_from_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify an issue from a pre-built context dict.
        Fresh connection per alert — same guarantee as classify_issue().

        Used by the detection engine to validate its findings through
        the FP Identifier without needing a CSV issue_id lookup.

        The context dict should contain at minimum:
            - repo_name, filename, rel_filename, line_number
            - alert_text (description of the issue)
            - code_snippet
        Optional: severity, cwe, issue_type, category,
                  readme, folder_structure
        """
        self.llm = LLMClient(self.config.llm)

        issue_id = context.get(
            "issue_id",
            f"det_{context.get('filename', 'unknown')}_{context.get('line_number', 0)}",
        )

        print(f"\n{'='*60}")
        print(f"Classifying detected issue: {issue_id} (mode: {self.config.mode})")
        print(f"  File: {context.get('filename', '?')}:{context.get('line_number', '?')}")
        print(f"  Type: {context.get('issue_type', '?')}")
        print(f"{'='*60}")

        defaults = {
            "issue_id": issue_id,
            "issue_location": f"{context.get('filename', '?')}:{context.get('line_number', 0)}",
            "tool": context.get("source_tool", "detection_engine"),
            "all_sources": context.get("source_tool", "detection_engine"),
            "tool_issue_id": context.get("tool_issue_id", ""),
            "severity": context.get("severity", "MEDIUM"),
            "cwe": context.get("cwe", ""),
        }

        for key, val in defaults.items():
            context.setdefault(key, val)

        if self.config.mode == "conversation":
            return self._classify_conversation(issue_id, context)
        else:
            return self._classify_stateless(issue_id, context)

    # ==========================================================
    # STATELESS MODE
    # ==========================================================
    # Each iteration rebuilds the full message list from scratch:
    # initial prompt + all previous tool call/result message pairs.

    def _classify_stateless(
        self, issue_id: str, context: Dict[str, Any],
    ) -> Dict[str, Any]:
        max_iter = self.config.fp_max_iterations
        seen: Dict[str, int] = {}
        tool_call_counts: Dict[str, int] = {}
        tool_call_history: List[Dict] = []

        initial_prompt = build_llm_prompt(context, self.config)
        api_history: List[List[Dict]] = []
        consecutive_parse_fails: int = 0

        for iteration in range(max_iter):
            num_iterations = iteration + 1
            print(f"  Iteration {num_iterations}/{max_iter}")

            messages: List[Dict] = [{"role": "user", "content": initial_prompt}]
            for msg_pair in api_history:
                messages.extend(msg_pair)

            if iteration == max_iter - 1:
                messages.append({
                    "role": "user",
                    "content": (
                        "You have used all investigation steps. You MUST classify this issue NOW "
                        "as TP, FP, or NON_ACTIONABLE based on what you have gathered so far. "
                        "Output JSON: {\"classification\": \"...\", \"reasoning\": \"...\"}"
                    ),
                })

            print(f"    Querying LLM... ({len(messages)} messages)")
            response = self.llm.query_messages_with_tools(
                messages, self._tool_definitions,
            )
            response_json = self._parse_response(response)

            if "error" in response_json and "classification" not in response_json:
                consecutive_parse_fails += 1
                raw_text = response_json.get("raw_response", "")
                print(f"    Error: {response_json.get('error', 'unknown')} (nudging model to JSON...)")
                if consecutive_parse_fails >= 2:
                    print(f"    Stuck after {consecutive_parse_fails} nudges — forcing classification")
                    return self._force_classification(
                        issue_id, num_iterations, "stateless",
                        context, tool_call_counts, tool_call_history, messages,
                    )
                nudge_pair: List[Dict] = []
                if raw_text:
                    nudge_pair.append({"role": "assistant", "content": raw_text})
                nudge_pair.append({
                    "role": "user",
                    "content": (
                        'OUTPUT ONLY JSON. No prose. Either '
                        '{"command":"TOOL_NAME","parameters":{}} '
                        'or {"classification":"TP|FP|NON_ACTIONABLE","reasoning":"..."}.'
                    ),
                })
                api_history.append(nudge_pair)
                continue

            consecutive_parse_fails = 0  # reset on any successful parse

            if "classification" in response_json:
                gate_c_result = self._gate_c_check(
                    str(response_json["classification"]).upper(),
                    response, context, tool_call_counts, tool_call_history,
                    messages, "stateless", issue_id, num_iterations,
                )
                if gate_c_result is not None:
                    return gate_c_result
                return self._build_classification_result(
                    issue_id, response_json, num_iterations,
                    tool_call_counts, tool_call_history,
                    "stateless", context,
                )

            command, parameters, call_id = self._extract_tool_call(response_json)

            if command and command in self.VALID_TOOLS:
                print(f"    Tool: {command}")

                tool_call_counts[command] = tool_call_counts.get(command, 0) + 1

                # Per-alert budgets for external-evidence tools
                budget_exceeded_msg = self._check_tool_budget(command, tool_call_counts)
                if budget_exceeded_msg:
                    print(f"    Budget exceeded: {budget_exceeded_msg}")
                    nudge_pair = [
                        {"role": "assistant", "content": str(response_json)[:200]},
                        {"role": "user", "content": budget_exceeded_msg},
                    ]
                    api_history.append(nudge_pair)
                    continue

                sig = self.tools.tool_signature(command, parameters, context["repo_name"])
                seen[sig] = seen.get(sig, 0) + 1
                if seen[sig] >= 3:
                    return self._force_classification(
                        issue_id, num_iterations, "stateless",
                        context, tool_call_counts, tool_call_history, messages,
                    )

                result = self.tools.execute(command, parameters, context["repo_name"], issue_id)
                print(f"    {'Success' if 'error' not in result else 'Error: ' + result.get('error', '')}")

                tool_call_history.append({
                    "iteration": num_iterations,
                    "command": command,
                    "parameters": parameters,
                    "result_summary": self.tools.summarize_result(command, result),
                    "success": result.get("success", False) if "error" not in result else False,
                })

                result_text = format_tool_result_content(command, result)
                msg_pair = self.llm.build_tool_call_history(
                    command, parameters, call_id, result_text,
                )
                api_history.append(msg_pair)
            else:
                consecutive_parse_fails += 1
                print(f"    Unexpected response format (nudging model to JSON...)")
                if consecutive_parse_fails >= 2:
                    return self._force_classification(
                        issue_id, num_iterations, "stateless",
                        context, tool_call_counts, tool_call_history, messages,
                    )
                nudge_pair = [
                    {"role": "assistant", "content": str(response_json)[:200]},
                    {
                        "role": "user",
                        "content": (
                            'OUTPUT ONLY JSON. No prose. Either '
                            '{"command":"TOOL_NAME","parameters":{}} '
                            'or {"classification":"TP|FP|NON_ACTIONABLE","reasoning":"..."}.'
                        ),
                    },
                ]
                api_history.append(nudge_pair)
                continue

        return self._force_classification(
            issue_id, max_iter, "stateless",
            context, tool_call_counts, tool_call_history, messages,
        )

    # ==========================================================
    # CONVERSATION MODE
    # ==========================================================
    # Send the full prompt once, then only append tool results.
    # The LLM's conversation memory keeps track of previous turns.

    def _classify_conversation(
        self, issue_id: str, context: Dict[str, Any],
    ) -> Dict[str, Any]:
        max_iter = self.config.fp_max_iterations

        initial_prompt = build_llm_prompt(context, self.config)
        messages: List[Dict] = [{"role": "user", "content": initial_prompt}]

        seen: Dict[str, int] = {}
        tool_call_counts: Dict[str, int] = {}
        tool_call_history: List[Dict] = []
        consecutive_parse_fails: int = 0

        print(f"  Iteration 1/{max_iter}")
        print(f"    Querying LLM... (initial: {len(initial_prompt)} chars)")

        for iteration in range(max_iter):
            num_iterations = iteration + 1

            if iteration == max_iter - 1:
                messages.append({
                    "role": "user",
                    "content": (
                        "You have used all investigation steps. You MUST classify this issue NOW "
                        "as TP, FP, or NON_ACTIONABLE based on what you have gathered so far. "
                        "Output JSON: {\"classification\": \"...\", \"reasoning\": \"...\"}"
                    ),
                })

            response = self.llm.query_messages_with_tools(
                messages, self._tool_definitions,
            )
            response_json = self._parse_response(response)

            if "error" in response_json and "classification" not in response_json:
                consecutive_parse_fails += 1
                raw_text = response_json.get("raw_response", "")
                print(f"    Error: {response_json.get('error', 'unknown')} (nudging model to JSON...)")
                # Cap at 2 consecutive failures — force-classify instead of spinning
                if consecutive_parse_fails >= 2:
                    print(f"    Stuck after {consecutive_parse_fails} nudges — forcing classification")
                    return self._force_classification(
                        issue_id, num_iterations, "conversation",
                        context, tool_call_counts, tool_call_history, messages,
                    )
                if raw_text:
                    messages.append({"role": "assistant", "content": raw_text})
                messages.append({
                    "role": "user",
                    "content": (
                        'OUTPUT ONLY JSON. No prose. Either '
                        '{"command":"TOOL_NAME","parameters":{}} '
                        'or {"classification":"TP|FP|NON_ACTIONABLE","reasoning":"..."}.'
                    ),
                })
                continue

            consecutive_parse_fails = 0  # reset on any successful parse

            if "classification" in response_json:
                gate_c_result = self._gate_c_check(
                    str(response_json["classification"]).upper(),
                    response, context, tool_call_counts, tool_call_history,
                    messages, "conversation", issue_id, num_iterations,
                )
                if gate_c_result is not None:
                    return gate_c_result
                return self._build_classification_result(
                    issue_id, response_json, num_iterations,
                    tool_call_counts, tool_call_history,
                    "conversation", context,
                )

            command, parameters, call_id = self._extract_tool_call(response_json)

            if command and command in self.VALID_TOOLS:
                if iteration > 0:
                    print(f"  Iteration {num_iterations}/{max_iter}")
                print(f"    Tool: {command}")

                tool_call_counts[command] = tool_call_counts.get(command, 0) + 1

                # Per-alert budgets for external-evidence tools
                budget_exceeded_msg = self._check_tool_budget(command, tool_call_counts)
                if budget_exceeded_msg:
                    print(f"    Budget exceeded: {budget_exceeded_msg}")
                    messages.append({"role": "assistant", "content": str(response_json)[:200]})
                    messages.append({"role": "user", "content": budget_exceeded_msg})
                    continue

                sig = self.tools.tool_signature(command, parameters, context["repo_name"])
                seen[sig] = seen.get(sig, 0) + 1
                if seen[sig] >= 3:
                    return self._force_classification(
                        issue_id, num_iterations, "conversation",
                        context, tool_call_counts, tool_call_history, messages,
                    )

                result = self.tools.execute(command, parameters, context["repo_name"], issue_id)
                print(f"    {'Success' if 'error' not in result else 'Error: ' + result.get('error', '')}")

                tool_call_history.append({
                    "iteration": num_iterations,
                    "command": command,
                    "parameters": parameters,
                    "result_summary": self.tools.summarize_result(command, result),
                    "success": result.get("success", False) if "error" not in result else False,
                })

                result_text = format_tool_result_content(command, result)
                msg_pair = self.llm.build_tool_call_history(
                    command, parameters, call_id, result_text,
                )
                messages.extend(msg_pair)

                print(f"    Sent tool result ({len(result_text)} chars)")
            else:
                consecutive_parse_fails += 1
                print(f"    Unexpected response format (nudging model to JSON...)")
                if consecutive_parse_fails >= 2:
                    return self._force_classification(
                        issue_id, num_iterations, "conversation",
                        context, tool_call_counts, tool_call_history, messages,
                    )
                messages.append({"role": "assistant", "content": str(response_json)[:200]})
                messages.append({
                    "role": "user",
                    "content": (
                        'OUTPUT ONLY JSON. No prose. Either '
                        '{"command":"TOOL_NAME","parameters":{}} '
                        'or {"classification":"TP|FP|NON_ACTIONABLE","reasoning":"..."}.'
                    ),
                })
                continue

        return self._force_classification(
            issue_id, max_iter, "conversation",
            context, tool_call_counts, tool_call_history, messages,
        )

    # ==========================================================
    # PER-ALERT TOOL BUDGETS
    # ==========================================================

    def _check_tool_budget(
        self, command: str, tool_call_counts: Dict[str, int],
    ) -> Optional[str]:
        """
        Return a nudge message if a per-alert budget is exceeded, else None.
        tool_call_counts has already been incremented for `command`.
        """
        count = tool_call_counts.get(command, 0)
        if command == "WEB_SEARCH" and count > self.MAX_WEB_SEARCH_PER_ALERT:
            return (
                f"WEB_SEARCH budget exceeded ({self.MAX_WEB_SEARCH_PER_ALERT} searches per alert). "
                "Stop searching. Pick the best URL you have already found and call WGET on it, "
                "or classify based on the evidence already gathered. "
                'Output ONLY JSON: {"classification":"TP|FP|NON_ACTIONABLE","reasoning":"..."}.'
            )
        if command == "WGET" and count > self.MAX_WGET_PER_ALERT:
            return (
                f"WGET budget exceeded ({self.MAX_WGET_PER_ALERT} fetches per alert). "
                "Stop fetching new URLs. Classify based on the evidence you have already gathered. "
                'Output ONLY JSON: {"classification":"TP|FP|NON_ACTIONABLE","reasoning":"..."}.'
            )
        if command == "CHECK_PACKAGE_STATUS" and count > self.MAX_CHECK_PACKAGE_PER_ALERT:
            return (
                f"CHECK_PACKAGE_STATUS budget exceeded "
                f"({self.MAX_CHECK_PACKAGE_PER_ALERT} lookups per alert). "
                "Stop calling this tool. Classify based on what you have. "
                'Output ONLY JSON: {"classification":"TP|FP|NON_ACTIONABLE","reasoning":"..."}.'
            )
        return None

    # ==========================================================
    # GATE C — POST-CLASSIFICATION DEPRECATED-PRIMITIVE GUARD
    # ==========================================================

    def _gate_c_check(
        self,
        classification: str,
        last_response: str,
        context: Dict[str, Any],
        tool_call_counts: Dict[str, int],
        tool_call_history: List[Dict],
        messages: List[Dict],
        mode: str,
        issue_id: str,
        num_iterations: int,
    ) -> Optional[Dict[str, Any]]:
        """
        Post-classification guard for known-deprecated primitives.

        Fires exactly once per alert when ALL of:
          1. Classification is FP or NON_ACTIONABLE (never fires on TP)
          2. Alert text or code snippet references a known-deprecated primitive
          3. Neither WEB_SEARCH nor CHECK_PACKAGE_STATUS was called during investigation

        One corrective re-iteration max — if the model still classifies FP/NA after
        the nudge, we accept it and return that result.  The gate NEVER loops.

        Logs every firing with before/after classification to tool_call_history so
        §6 ablation data is real.

        Returns the new classification result dict, or None if the gate does not fire.
        """
        # Mitigation 1: only gate FP/NA, never TP
        if classification not in ("FP", "NON_ACTIONABLE"):
            return None

        # Mitigation 2: if the model already investigated via external-evidence tools, accept result
        tools_used = set(tool_call_counts.keys())
        already_investigated = bool(tools_used & {"WEB_SEARCH", "CHECK_PACKAGE_STATUS"})
        if already_investigated:
            return None

        # Mitigation 3: match strictly against alert text + code snippet + alert rule ID
        # (NOT README, NOT folder_structure, NOT tool results — avoids unrelated-file triggers)
        alert_target = (
            context.get("alert_text", "")
            + " " + context.get("code_snippet", "")
            + " " + context.get("tool_issue_id", "")
        )

        triggered_by = None
        for pattern, label in self._GATE_C_PATTERNS:
            if re.search(pattern, alert_target, re.IGNORECASE):
                triggered_by = label
                break

        if triggered_by is None:
            return None

        # Gate C fires — log it
        print(
            f"  [Gate C] FIRING for issue #{issue_id}: "
            f"deprecated primitive '{triggered_by}' in alert/code; "
            f"classification was {classification} without WEB_SEARCH/CHECK_PACKAGE_STATUS."
        )

        nudge = (
            f"⛔ GATE C VIOLATION — You classified {classification} on an alert that involves "
            f"the known-deprecated primitive '{triggered_by}', but you did NOT call "
            f"WEB_SEARCH or CHECK_PACKAGE_STATUS to verify its current status. "
            f"You MUST do ONE of the following before finalising:\n"
            f"  (a) Call WEB_SEARCH to confirm the deprecation status of '{triggered_by}', OR\n"
            f"  (b) Call CHECK_PACKAGE_STATUS if this alert involves a package dependency, OR\n"
            f"  (c) Reclassify as TP now, acknowledging that '{triggered_by}' is "
            f"a standards-body-deprecated primitive with no WEB_SEARCH evidence of a carve-out.\n"
            f"This is a ONE-TIME corrective step. Output ONLY JSON: "
            f'{{\"classification\":\"TP|FP|NON_ACTIONABLE\",\"reasoning\":\"...\"}}.'
        )

        # Append model's last response then the Gate C nudge so the model has context
        messages_with_nudge = list(messages)  # shallow copy — do not mutate caller's list
        messages_with_nudge.append({"role": "assistant", "content": last_response[:2000]})
        messages_with_nudge.append({"role": "user", "content": nudge})

        tool_call_history.append({
            "iteration": num_iterations,
            "action": "GATE_C_NUDGE",
            "triggered_by": triggered_by,
            "original_classification": classification,
            "success": True,
        })

        response = self.llm.query_messages_with_tools(messages_with_nudge, self._tool_definitions)
        response_json = self._parse_response(response)

        new_classification = None
        if "classification" in response_json:
            new_classification = str(response_json["classification"]).upper()
        else:
            # Try plain-text extraction if JSON parse failed
            raw = response.upper()
            for label in ("NON_ACTIONABLE", "FP", "TP"):
                if re.search(rf'\b{label}\b', raw):
                    new_classification = label
                    response_json = {"classification": label, "reasoning": response[:1500]}
                    break

        if new_classification is None:
            # Could not parse nudge response — keep original, gate is done
            print(f"  [Gate C] Could not parse nudge response; keeping original: {classification}")
            tool_call_history.append({
                "iteration": num_iterations + 1,
                "action": "GATE_C_RESULT",
                "triggered_by": triggered_by,
                "original_classification": classification,
                "new_classification": None,
                "flipped": False,
                "parse_failed": True,
                "success": False,
            })
            return None

        flipped = new_classification != classification
        print(
            f"  [Gate C] Result for issue #{issue_id}: "
            f"{classification} → {new_classification} "
            f"({'FLIPPED' if flipped else 'unchanged'})"
        )
        tool_call_history.append({
            "iteration": num_iterations + 1,
            "action": "GATE_C_RESULT",
            "triggered_by": triggered_by,
            "original_classification": classification,
            "new_classification": new_classification,
            "flipped": flipped,
            "success": True,
        })

        return self._build_classification_result(
            issue_id, response_json, num_iterations + 1,
            tool_call_counts, tool_call_history,
            mode, context,
        )

    # ==========================================================
    # TOOL CALL EXTRACTION
    # ==========================================================

    def _extract_tool_call(self, response_json: Dict) -> tuple:
        """
        Extract tool command, parameters, and call_id from a parsed response.

        Handles multiple formats that different models produce:
          - Native:  {"command": "SEARCH", "parameters": {...}, "_call_id": "..."}
          - Alt key:   {"action": "SEARCH", "parameters": {...}}
          - Text tool: {"name": "SEARCH", "arguments": {...}}

        Returns:
            (command, parameters, call_id) or (None, {}, "")
        """
        if isinstance(response_json, list):
            for item in response_json:
                if isinstance(item, dict):
                    response_json = item
                    break
            else:
                return None, {}, ""

        # Ollama native tool-call format: {"tool_calls": [{"id": "...", "function": {"name": "...", "arguments": "..."}}]}
        tcs = response_json.get("tool_calls")
        if tcs and isinstance(tcs, list) and tcs:
            fn = tcs[0].get("function", {})
            if fn.get("name") in self.VALID_TOOLS:
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                return fn["name"], args, tcs[0].get("id", "")

        command = response_json.get("command")

        if not command and response_json.get("action") in self.VALID_TOOLS:
            command = response_json["action"]

        if not command and response_json.get("name") in self.VALID_TOOLS:
            command = response_json["name"]

        if not command:
            return None, {}, ""

        parameters = (
            response_json.get("parameters")
            or response_json.get("arguments")
            or {}
        )
        call_id = response_json.get("_call_id", "")

        return command, parameters, call_id

    # ==========================================================
    # RESPONSE PARSING
    # ==========================================================

    def _parse_response(self, response: str) -> Dict[str, Any]:
        try:
            parsed = json.loads(response)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        return item
                return {"error": "LLM returned a JSON list with no dict elements"}
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            if end > start:
                try:
                    return json.loads(response[start:end].strip())
                except json.JSONDecodeError:
                    pass

        start = response.find("{")
        end = response.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(response[start : end + 1])
            except json.JSONDecodeError:
                pass

        # Last resort: scan plain-text for classification keywords.
        # Local models (Qwen, LLaMA) sometimes write full reasoning in prose.
        upper = response.upper()

        # Pattern A: explicit "classification: X" / "verdict: X" / "final answer: X"
        m = re.search(
            r'(?:CLASSIFICATION|VERDICT|FINAL\s+ANSWER)["\s:*]+\s*(NON_ACTIONABLE|TP|FP)\b',
            upper,
        )
        if m:
            if self.config.debug:
                print(f"    Extracted '{m.group(1)}' via label pattern from plain-text")
            return {"classification": m.group(1), "reasoning": response[:1500]}

        # Pattern B: short response containing exactly one label
        if len(response) < 600:
            labels_seen = [L for L in ("NON_ACTIONABLE", "FP", "TP")
                           if re.search(rf'\b{L}\b', upper)]
            if len(labels_seen) == 1:
                if self.config.debug:
                    print(f"    Extracted '{labels_seen[0]}' (sole token) from short plain-text")
                return {"classification": labels_seen[0], "reasoning": response[:1500]}

        if self.config.debug:
            print(f"\n{'='*60}")
            print("FAILED TO PARSE LLM RESPONSE")
            print(f"RAW (first 2000 chars):\n{response[:2000]}")
            print(f"{'='*60}\n")

        return {
            "error": "Failed to parse LLM response as JSON",
            "raw_response": response[:500],
        }

    # ==========================================================
    # RESULT BUILDERS
    # ==========================================================

    def _build_classification_result(
        self,
        issue_id: str,
        response_json: Dict,
        num_iterations: int,
        tool_call_counts: Dict[str, int],
        tool_call_history: List[Dict],
        mode: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        classification = str(response_json["classification"]).upper()
        reasoning = response_json.get("reasoning", "")

        if classification not in {"FP", "TP", "NON_ACTIONABLE"}:
            return self._error_result(
                issue_id, f"Invalid classification: {classification}", num_iterations,
            )

        print(f"    Classification: {classification}")

        tool_call_history.append({
            "iteration": num_iterations,
            "action": "CLASSIFY",
            "classification": classification,
            "reasoning": reasoning,
            "success": True,
        })

        all_sources = context.get("all_sources", context.get("tool", "Unknown"))
        tools = [t.strip() for t in all_sources.split("|")] if "|" in all_sources else [all_sources]

        return {
            "issue_id": issue_id,
            "classification": classification,
            "reasoning": reasoning,
            "num_iterations": num_iterations,
            "tool_call_counts": tool_call_counts,
            "tool_call_history": tool_call_history,
            "mode": mode,
            "source_tools": tools,
            "success": True,
        }

    def _error_result(
        self, issue_id: str, error_msg: str, num_iterations: int,
    ) -> Dict[str, Any]:
        return {
            "issue_id": issue_id,
            "classification": "ERROR",
            "reasoning": error_msg,
            "num_iterations": num_iterations,
            "success": False,
        }

    def _force_classification(
        self,
        issue_id: str,
        num_iterations: int,
        mode: str,
        context: Dict[str, Any],
        tool_call_counts: Dict[str, int],
        tool_call_history: List[Dict],
        messages: List[Dict],
    ) -> Dict[str, Any]:
        """Force the LLM to classify when stuck. Never returns ERROR."""
        print(f"    Forcing classification...")
        messages.append({
            "role": "user",
            "content": (
                "STOP using tools. You MUST classify this issue RIGHT NOW. "
                "Respond ONLY with JSON: {\"classification\": \"TP|FP|NON_ACTIONABLE\", "
                "\"reasoning\": \"...\"}. "
                "If unsure, classify as TP. No tool calls. JSON only."
            ),
        })

        for attempt in range(3):
            response = self.llm.query_messages_with_tools(messages, self._tool_definitions)
            response_json = self._parse_response(response)

            if "classification" in response_json:
                return self._build_classification_result(
                    issue_id, response_json, num_iterations,
                    tool_call_counts, tool_call_history,
                    mode, context,
                )

            raw = response.upper()
            for label in ("NON_ACTIONABLE", "FP", "TP"):
                if re.search(rf'\b{label}\b', raw):
                    print(f"    Extracted '{label}' from unstructured forced response (attempt {attempt+1})")
                    return self._build_classification_result(
                        issue_id,
                        {"classification": label, "reasoning": "Forced classification (extracted from text)"},
                        num_iterations, tool_call_counts, tool_call_history,
                        mode, context,
                    )

        print(f"    Force failed after 3 attempts — defaulting to TP")
        return self._build_classification_result(
            issue_id,
            {"classification": "TP", "reasoning": "Default TP — model failed to classify after forced attempts"},
            num_iterations, tool_call_counts, tool_call_history,
            mode, context,
        )
