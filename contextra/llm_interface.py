"""
llm_interface.py — Generic LLM Client with Native Tool Calling
================================================================

A single LLMClient class that talks to ANY provider using native
tool calling for investigation tools:
  - Claude   (Anthropic SDK — tools= parameter, tool_use content blocks)
  - GPT      (OpenAI SDK — tools= parameter, tool_calls response)
  - Ollama   (OpenAI SDK with custom base_url — same as GPT)

Design:
  - Investigation tools (SEARCH, GET, etc.) are passed via tools= parameter
  - Classification is done via text response (no CLASSIFY tool)
  - response_format=json_object is NOT used (conflicts with tools= on Ollama)
  - Prompt instructs "Respond with JSON only" for classification text
  - _ensure_json() handles extraction from messy text responses

USAGE:
    from config import load_config
    from llm_interface import LLMClient, get_tool_definitions

    config = load_config()
    llm = LLMClient(config.llm)
    tools = get_tool_definitions()

    # Single prompt with tools (stateless mode):
    response = llm.query_with_tools("Classify this alert...", tools)

    # Conversation with tools (conversation mode):
    response = llm.query_messages_with_tools(messages, tools)

    # Build conversation history after a tool call:
    history_msgs = llm.build_tool_call_history(
        "SEARCH", {"pattern": "password"}, "call_1", "results..."
    )
    messages.extend(history_msgs)
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List

from config import LLMConfig

logger = logging.getLogger(__name__)


# =====================================================
# TOOL DEFINITIONS (OpenAI function-calling format)
# =====================================================
# Stored in OpenAI format because 2 of 3 providers use it directly.
# Converted to Anthropic format internally for Claude.

TOOL_DEFINITIONS: List[Dict] = [
    {
        "type": "function",
        "function": {
            "name": "SEARCH",
            "description": (
                "Grep all source files in the repository for a pattern. "
                "Supports regex. Returns filename, line_number, and preview for each match."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Search pattern (regex supported, case-insensitive)",
                    },
                    "max_matches": {
                        "type": "integer",
                        "description": "Maximum matches to return (default: 50)",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "GET",
            "description": (
                "Read lines from a file. Lines are 1-indexed. "
                "Use to inspect code at locations found by SEARCH. "
                "If line_start/line_end omitted, reads from the beginning."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Path to the file relative to repo root",
                    },
                    "line_start": {
                        "type": "integer",
                        "description": "First line to read (1-indexed, default: 1)",
                    },
                    "line_end": {
                        "type": "integer",
                        "description": "Last line to read (1-indexed, default: line_start + 50)",
                    },
                },
                "required": ["filename"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "GET_FUNCTION",
            "description": (
                "Get the complete function/method definition containing a given line. "
                "Returns the full function body with line numbers."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Path to the file relative to repo root",
                    },
                    "line_number": {
                        "type": "integer",
                        "description": "Line number inside the function to retrieve",
                    },
                },
                "required": ["filename", "line_number"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "GET_FILE",
            "description": (
                "Read entire file contents (max 100KB). "
                "Use for small files when you need full context."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Path to the file relative to repo root",
                    },
                },
                "required": ["filename"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "LIST_DIRECTORY",
            "description": (
                "List source files and subdirectories at a given path. "
                "Use '.' for the repo root."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Directory path relative to repo root (use '.' for root)",
                    },
                },
                "required": ["directory"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "GET_SUBGRAPH",
            "description": (
                "Get call graph (callers + callees) around a function. "
                "Use to understand how a function is called and what it calls."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "node": {
                        "type": "string",
                        "description": "Function name to look up in the call graph",
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Traversal depth (1=direct, 2=two hops, max 3)",
                    },
                },
                "required": ["node"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "GET_PREDECESSOR",
            "description": (
                "Get all functions that call a specific function (callers only). "
                "Simpler than GET_SUBGRAPH when you only need callers."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "node": {
                        "type": "string",
                        "description": "Function name to find callers of",
                    },
                },
                "required": ["node"],
            },
        },
    },
]

SEMGREP_TOOL: Dict = {
    "type": "function",
    "function": {
        "name": "RUN_SEMGREP",
        "description": (
            "Run Semgrep analysis on the repository. "
            "Modes: 'crypto' = crypto rules, 'general' = all rules, "
            "'custom' = provide YAML rule in custom_rule parameter."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["crypto", "general", "custom"],
                    "description": "Analysis mode",
                },
                "custom_rule": {
                    "type": "string",
                    "description": "YAML rule content (only for 'custom' mode)",
                },
            },
            "required": ["mode"],
        },
    },
}

CODEQL_TOOL: Dict = {
    "type": "function",
    "function": {
        "name": "RUN_CODEQL",
        "description": (
            "Run CodeQL analysis on the repository. "
            "Modes: 'crypto' = crypto queries, 'general' = all queries, "
            "'custom' = provide .ql query in custom_query parameter."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["crypto", "general", "custom"],
                    "description": "Analysis mode",
                },
                "custom_query": {
                    "type": "string",
                    "description": "QL query content (only for 'custom' mode)",
                },
            },
            "required": ["mode"],
        },
    },
}


VALIDATE_ISSUE_TOOL: Dict = {
    "type": "function",
    "function": {
        "name": "VALIDATE_ISSUE",
        "description": (
            "Validate a detected issue by running the FP Identifier agent on it. "
            "The FP Identifier will investigate the code using its own tools and classify "
            "the issue as TP (true positive), FP (false positive), or NON_ACTIONABLE. "
            "Use this to verify your findings before including them in the final report. "
            "If the result is FP or NON_ACTIONABLE, you should discard the issue."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Path to the file containing the issue (relative to repo root)",
                },
                "line_number": {
                    "type": "integer",
                    "description": "Line number of the issue",
                },
                "issue_type": {
                    "type": "string",
                    "description": "Type of issue — your expert classification of the misuse",
                },
                "description": {
                    "type": "string",
                    "description": "Your description of the issue",
                },
            },
            "required": ["filename", "line_number", "issue_type", "description"],
        },
    },
}


def get_tool_definitions(ablation_config: str = "9tool") -> List[Dict]:
    """Return investigation tool definitions for the given ablation config.

    Configs:
        "9tool"          → all 9 tools
        "9tool_searchcap"→ all 9 tools (cap enforced in tools.py, not here)
        "6tool"          → remove SEARCH, GET, GET_FUNCTION (keep GET_FILE full)
        "8tool"          → remove SEARCH (keep GET, GET_FUNCTION)
        "7tool_nosast"   → remove RUN_SEMGREP, RUN_CODEQL
    """
    _REMOVE_MAP = {
        "9tool": set(),
        "9tool_searchcap": set(),
        "6tool": {"SEARCH", "GET", "GET_FUNCTION"},
        "8tool": {"SEARCH"},
        "7tool_nosast": set(),
    }
    remove_names = _REMOVE_MAP.get(ablation_config, set())

    tools = [t for t in TOOL_DEFINITIONS if t["function"]["name"] not in remove_names]

    if ablation_config != "7tool_nosast":
        tools.append(SEMGREP_TOOL)
        tools.append(CODEQL_TOOL)

    return tools


_DETECTION_TOOL_NAMES = {
    "SEARCH", "GET", "GET_FILE", "GET_FUNCTION", "LIST_DIRECTORY",
    "GET_SUBGRAPH", "GET_PREDECESSOR",
}


def get_detection_tool_definitions() -> List[Dict]:
    """
    Return all 10 tool definitions for the detection engine
    (9 investigation + VALIDATE_ISSUE).
    """
    tools = [t for t in TOOL_DEFINITIONS if t["function"]["name"] in _DETECTION_TOOL_NAMES]
    tools.append(SEMGREP_TOOL)
    tools.append(CODEQL_TOOL)
    tools.append(VALIDATE_ISSUE_TOOL)
    return tools


def get_detection_investigation_tools() -> List[Dict]:
    """
    Return 9 investigation-only tools for Phase 1 of detection.
    VALIDATE_ISSUE is excluded — validation happens in Phase 2 via code.
    """
    tools = [t for t in TOOL_DEFINITIONS if t["function"]["name"] in _DETECTION_TOOL_NAMES]
    tools.append(SEMGREP_TOOL)
    tools.append(CODEQL_TOOL)
    return tools


def _to_claude_tools(openai_tools: List[Dict]) -> List[Dict]:
    """Convert OpenAI function-calling format to Anthropic tool format."""
    return [
        {
            "name": t["function"]["name"],
            "description": t["function"]["description"],
            "input_schema": t["function"]["parameters"],
        }
        for t in openai_tools
    ]


class LLMClient:
    """
    Generic LLM client with native tool calling for all providers.

    Internally uses:
      - anthropic.Anthropic    for Claude  (tools= → tool_use content blocks)
      - openai.OpenAI          for GPT     (tools= → tool_calls array)
      - openai.OpenAI          for Ollama  (tools= → tool_calls array, OpenAI-compat)

    Investigation tools are native (tools= parameter).
    Classification is via text response, parsed by _ensure_json().
    Prompt instructs "Respond with JSON only" for classification.
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self.provider = config.provider
        self.model = config.model
        self._call_counter = 0

        if self.provider == "claude":
            self._init_claude(config)
        elif self.provider == "openai":
            self._init_openai(config)
        elif self.provider == "ollama":
            self._init_ollama(config)
        else:
            raise ValueError(f"Unknown provider: '{self.provider}'")

        logger.info("LLM ready: %s / %s (native tool calling)", self.provider, self.model)

    # ---------------------------------------------------------
    # Provider initialization
    # ---------------------------------------------------------

    def _init_claude(self, config: LLMConfig) -> None:
        if not config.api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set.")
        import anthropic
        self._client = anthropic.Anthropic(api_key=config.api_key)

    def _init_openai(self, config: LLMConfig) -> None:
        if not config.api_key:
            raise ValueError("OPENAI_API_KEY is not set.")
        from openai import OpenAI
        kwargs: Dict[str, Any] = {"api_key": config.api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        else:
            os.environ.pop("OPENAI_BASE_URL", None)
        self._client = OpenAI(**kwargs)

    def _init_ollama(self, config: LLMConfig) -> None:
        from openai import OpenAI
        base_url = config.base_url.rstrip("/") + "/v1"
        self._client = OpenAI(base_url=base_url, api_key="ollama")

    # ---------------------------------------------------------
    # Public API — native tool calling
    # ---------------------------------------------------------

    def query_with_tools(self, prompt: str, tools: List[Dict]) -> str:
        """
        Send a single prompt with native tools (stateless mode).

        Returns a JSON string in one of two formats:
          Tool call:      {"command": "SEARCH", "parameters": {...}, "_call_id": "..."}
          Classification: {"classification": "TP", "reasoning": "..."}
        """
        messages = [{"role": "user", "content": prompt}]
        return self._dispatch(messages, tools)

    def query_messages_with_tools(self, messages: List, tools: List[Dict]) -> str:
        """
        Send a conversation with native tools (conversation mode).

        Same return format as query_with_tools().
        """
        return self._dispatch(messages, tools)

    # ---------------------------------------------------------
    # Conversation history builder
    # ---------------------------------------------------------

    def build_tool_call_history(
        self,
        command: str,
        parameters: Dict[str, Any],
        call_id: str,
        tool_result_text: str,
    ) -> List[Dict]:
        """
        Build provider-specific message pair for conversation history.

        After a tool call, the conversation needs two messages:
          1. Assistant message (recording which tool was called)
          2. Tool result message (providing the result)

        The format differs between providers:
          OpenAI/Ollama: assistant.tool_calls + role="tool"
          Claude:        assistant.content[tool_use] + user.content[tool_result]
        """
        if not call_id:
            self._call_counter += 1
            call_id = f"call_{command.lower()}_{self._call_counter}"

        if self.provider == "claude":
            return [
                {
                    "role": "assistant",
                    "content": [{
                        "type": "tool_use",
                        "id": call_id,
                        "name": command,
                        "input": parameters,
                    }],
                },
                {
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": call_id,
                        "content": tool_result_text,
                    }],
                },
            ]
        else:
            return [
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": command,
                            "arguments": json.dumps(parameters),
                        },
                    }],
                },
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": tool_result_text,
                },
            ]

    # ---------------------------------------------------------
    # Internal dispatch
    # ---------------------------------------------------------

    def _dispatch(self, messages: List, tools: List[Dict]) -> str:
        try:
            if self.provider == "claude":
                return self._query_claude_native(messages, tools)
            else:
                return self._query_openai_native(messages, tools)
        except Exception as e:
            return json.dumps({"error": f"LLM API error: {e}"})

    # ---------------------------------------------------------
    # Native tool calling: OpenAI / Ollama
    # ---------------------------------------------------------

    def _query_openai_native(self, messages: List, tools: List[Dict]) -> str:
        """
        Call OpenAI or Ollama with native tool calling.

        Two response types:
          - Tool call: model calls SEARCH/GET/etc → structured tool_calls
          - Text: model wants to classify → parsed by _ensure_json

        NOTE: response_format=json_object is NOT used here because it
        conflicts with tools= on Ollama — the model outputs tool calls
        as JSON text instead of using the native tool_calls mechanism.
        The prompt instructs "Respond with JSON only" and _ensure_json
        handles extraction from text responses.
        """
        params: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
        }

        is_gpt5 = self.model.startswith("gpt-5")
        if is_gpt5:
            # GPT-5 family: reasoning models that don't support temperature
            # (only default=1 allowed when reasoning is active).
            # reasoning_effort: "none"|"low"|"medium"|"high"|"xhigh"
            #   - gpt-5.4 defaults to "none" (no reasoning) if not set
            #   - gpt-5, gpt-5.1 default to "medium"
            # max_completion_tokens: reasoning tokens + visible output share
            # this budget, so we enforce a minimum of 8000 to prevent
            # truncation where reasoning exhausts the cap before output.
            params["reasoning_effort"] = self.config.reasoning_effort
            params["max_completion_tokens"] = max(self.config.max_tokens, 8000)
        else:
            params["temperature"] = self.config.temperature
            if self.provider == "ollama":
                params["max_tokens"] = self.config.max_tokens
            else:
                params["max_completion_tokens"] = self.config.max_tokens

        response = self._client.chat.completions.create(**params)
        message = response.choices[0].message

        if message.tool_calls and len(message.tool_calls) > 0:
            tc = message.tool_calls[0]
            return self._normalize_tool_call(
                tc.function.name, tc.function.arguments, tc.id,
            )

        if message.content:
            text_tool = self._detect_text_tool_call(message.content)
            if text_tool:
                return text_tool
            return self._ensure_json(message.content)

        return json.dumps({"error": "Empty LLM response (no tool call, no text)"})

    # ---------------------------------------------------------
    # Native tool calling: Claude
    # ---------------------------------------------------------

    def _query_claude_native(self, messages: List, tools: List[Dict]) -> str:
        """
        Call Anthropic Claude with native tool calling.

        Claude uses a different format:
          - System prompt must be passed as a top-level `system` parameter,
            not as a message with role="system"
          - tools= takes {name, description, input_schema} (not OpenAI's nested format)
          - Tool calls appear as content blocks with type="tool_use"
          - Tool results go in user messages as type="tool_result"
        """
        claude_tools = _to_claude_tools(tools)

        # Extract system message — Claude API requires it as a separate parameter
        system_text = None
        non_system_messages = []
        for msg in messages:
            if msg.get("role") == "system":
                system_text = msg.get("content", "")
            else:
                non_system_messages.append(msg)

        kwargs = {
            "model": self.model,
            "messages": non_system_messages,
            "tools": claude_tools,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }
        if system_text:
            kwargs["system"] = [
                {
                    "type": "text",
                    "text": system_text,
                    "cache_control": {"type": "ephemeral"},
                }
            ]

        # Cache tool definitions — mark the last tool so the entire
        # tools list is cached across iterations (same 9 tools every call)
        if claude_tools:
            claude_tools[-1]["cache_control"] = {"type": "ephemeral"}

        response = self._client.messages.create(**kwargs)

        for block in response.content:
            if block.type == "tool_use":
                args_str = json.dumps(block.input) if isinstance(block.input, dict) else str(block.input)
                return self._normalize_tool_call(block.name, args_str, block.id)

        for block in response.content:
            if block.type == "text" and block.text.strip():
                return self._ensure_json(block.text)

        return json.dumps({"error": "Empty Claude response"})

    # ---------------------------------------------------------
    # Response normalization
    # ---------------------------------------------------------

    def _normalize_tool_call(self, func_name: str, func_args_str: str, call_id: str) -> str:
        """
        Convert a native tool call into the JSON format the classifier expects.

        Returns: {"command": "SEARCH", "parameters": {...}, "_call_id": "..."}
        """
        try:
            func_args = json.loads(func_args_str) if isinstance(func_args_str, str) else func_args_str
        except json.JSONDecodeError:
            func_args = {}

        return json.dumps({
            "command": func_name,
            "parameters": func_args,
            "reason": f"Tool call: {func_name}",
            "_call_id": call_id,
        })

    # ---------------------------------------------------------
    # Text-based tool call detection
    # ---------------------------------------------------------

    def _detect_text_tool_call(self, text: str) -> str | None:
        """
        Detect when a model outputs a tool call as text instead of using
        the native tool_calls mechanism.

        Some Ollama models (e.g., qwen2.5-coder) write tool calls as:
            {"name": "SEARCH", "arguments": {"pattern": "..."}}
        instead of using message.tool_calls. We detect this and convert
        it to the normalized format the classifier expects.
        """
        try:
            data = json.loads(text.strip())
        except (json.JSONDecodeError, ValueError):
            return None

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get("name"):
                    data = item
                    break
            else:
                return None

        name = data.get("name", "")
        arguments = data.get("arguments", {})

        if name and isinstance(arguments, dict):
            self._call_counter += 1
            call_id = f"call_text_{name.lower()}_{self._call_counter}"
            return json.dumps({
                "command": name,
                "parameters": arguments,
                "reason": f"Tool call (text): {name}",
                "_call_id": call_id,
            })

        return None

    # ---------------------------------------------------------
    # JSON safety (fallback for text responses)
    # ---------------------------------------------------------

    def _ensure_json(self, raw_response: str) -> str:
        """
        Ensure the response is valid JSON.

        For OpenAI/Ollama, response_format=json_object guarantees valid JSON.
        For Claude, text is usually valid JSON but we add fallback extraction.
        """
        if not raw_response:
            return json.dumps({"error": "Empty LLM response"})

        raw = raw_response.strip()

        try:
            json.loads(raw)
            return raw
        except json.JSONDecodeError:
            pass

        code_block = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', raw, re.DOTALL)
        if code_block:
            extracted = code_block.group(1).strip()
            try:
                json.loads(extracted)
                return extracted
            except json.JSONDecodeError:
                pass

        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            candidate = raw[start:end + 1]
            try:
                json.loads(candidate)
                return candidate
            except json.JSONDecodeError:
                pass

        return raw
