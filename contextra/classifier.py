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
from pathlib import Path
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

    _TOOLS_BY_CONFIG = {
        "9tool": {
            "GET", "GET_FILE", "GET_FUNCTION", "SEARCH",
            "LIST_DIRECTORY", "GET_SUBGRAPH", "GET_PREDECESSOR",
            "RUN_SEMGREP", "RUN_CODEQL",
        },
        "9tool_searchcap": {
            "GET", "GET_FILE", "GET_FUNCTION", "SEARCH",
            "LIST_DIRECTORY", "GET_SUBGRAPH", "GET_PREDECESSOR",
            "RUN_SEMGREP", "RUN_CODEQL",
        },
        "6tool": {
            "GET_FILE",
            "LIST_DIRECTORY", "GET_SUBGRAPH", "GET_PREDECESSOR",
            "RUN_SEMGREP", "RUN_CODEQL",
        },
        "8tool": {
            "GET", "GET_FILE", "GET_FUNCTION",
            "LIST_DIRECTORY", "GET_SUBGRAPH", "GET_PREDECESSOR",
            "RUN_SEMGREP", "RUN_CODEQL",
        },
        "7tool_nosast": {
            "GET", "GET_FILE", "GET_FUNCTION", "SEARCH",
            "LIST_DIRECTORY", "GET_SUBGRAPH", "GET_PREDECESSOR",
        },
    }

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

        ablation = getattr(config, "ablation_config", "9tool")
        self.VALID_TOOLS = self._TOOLS_BY_CONFIG.get(ablation, self._TOOLS_BY_CONFIG["9tool"])
        self._tool_definitions = get_tool_definitions(ablation)
        print(f"  Ablation config: {ablation}")
        print(f"  Valid tools: {sorted(self.VALID_TOOLS)}")
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

        file_path = self.config.paths.repos_dir / repo_name / rel_filename
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

        Used by the detection engine to validate its findings through
        the FP Identifier without needing a CSV issue_id lookup.

        The context dict should contain at minimum:
            - repo_name, filename, rel_filename, line_number
            - alert_text (description of the issue)
            - code_snippet
        Optional: severity, cwe, issue_type, category,
                  readme, folder_structure
        """
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

        ablation = getattr(self.config, "ablation_config", "9tool")
        initial_prompt = build_llm_prompt(context, self.config, ablation)
        api_history: List[List[Dict]] = []

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
                        "Output JSON only: {\"classification\": \"...\", \"reasoning\": \"...\"}"
                    ),
                })

            print(f"    Querying LLM... ({len(messages)} messages)")
            response = self.llm.query_messages_with_tools(
                messages, self._tool_definitions,
            )
            response_json = self._parse_response(response)

            if "error" in response_json and "classification" not in response_json:
                print(f"    Error: {response_json.get('error', 'unknown')} (retrying...)")
                continue

            if "classification" in response_json:
                return self._build_classification_result(
                    issue_id, response_json, num_iterations,
                    tool_call_counts, tool_call_history,
                    "stateless", context,
                )

            command, parameters, call_id = self._extract_tool_call(response_json)

            if command and command in self.VALID_TOOLS:
                print(f"    Tool: {command}")

                tool_call_counts[command] = tool_call_counts.get(command, 0) + 1

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

                result_text = format_tool_result_content(command, result, ablation)
                msg_pair = self.llm.build_tool_call_history(
                    command, parameters, call_id, result_text,
                )
                api_history.append(msg_pair)
            else:
                print(f"    Unexpected response format (retrying...)")
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

        ablation = getattr(self.config, "ablation_config", "9tool")
        initial_prompt = build_llm_prompt(context, self.config, ablation)
        messages: List[Dict] = [{"role": "user", "content": initial_prompt}]

        seen: Dict[str, int] = {}
        tool_call_counts: Dict[str, int] = {}
        tool_call_history: List[Dict] = []

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
                        "Output JSON only: {\"classification\": \"...\", \"reasoning\": \"...\"}"
                    ),
                })

            response = self.llm.query_messages_with_tools(
                messages, self._tool_definitions,
            )
            response_json = self._parse_response(response)

            if "error" in response_json and "classification" not in response_json:
                print(f"    Error: {response_json.get('error', 'unknown')} (retrying...)")
                continue

            if "classification" in response_json:
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

                result_text = format_tool_result_content(command, result, ablation)
                msg_pair = self.llm.build_tool_call_history(
                    command, parameters, call_id, result_text,
                )
                messages.extend(msg_pair)

                print(f"    Sent tool result ({len(result_text)} chars)")
            else:
                print(f"    Unexpected response format (retrying...)")
                continue

        return self._force_classification(
            issue_id, max_iter, "conversation",
            context, tool_call_counts, tool_call_history, messages,
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
                "Respond ONLY with JSON: {\"classification\": \"TP\", \"reasoning\": \"...\"} "
                "or {\"classification\": \"FP\", \"reasoning\": \"...\"} "
                "or {\"classification\": \"NON_ACTIONABLE\", \"reasoning\": \"...\"}. "
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
                if label in raw:
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
