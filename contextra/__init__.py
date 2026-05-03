"""
ContexTra — Agentic LLM System for Cryptographic API Misuse Alert Triage
=========================================================================

Files:
    config.py          — All configuration (dataclasses + .env loading)
    llm_interface.py   — Generic LLM client (Claude / GPT / Ollama)
    tools.py           — 9 investigation tools (+ RUN_SEMGREP + RUN_CODEQL)
    prompts.py         — Prompt templates and formatting
    classifier.py      — The agentic classification loop
    main.py            — CLI entry point

USAGE:
    cp .env.example .env        # then edit .env with your API keys
    python main.py              # run with defaults from .env
    python main.py --provider claude --config 9tool
    python main.py --provider ollama --model llama3.3:70b
"""

