"""
ContexTra Case Study — Extended Agentic LLM System (11 tools)
=============================================================

Extends the base ContexTra agent with WEB_SEARCH and CHECK_PACKAGE_STATUS
tools for the case study evaluation.

Files:
    config.py          — All configuration (dataclasses + .env loading)
    llm_interface.py   — Generic LLM client (Claude / GPT / Ollama)
    tools.py           — All analysis tools (9 base + WEB_SEARCH + CHECK_PACKAGE_STATUS)
    prompts.py         — Prompt templates and formatting
    classifier.py      — The agentic classification loop
    main.py            — CLI entry point

USAGE:
    cd case_study
    python main.py              # run with defaults from .env
    python main.py --provider claude --mode conversation
    python main.py --provider ollama --model llama3.3:70b --language python
    python main.py --provider ollama --model qwen2.5:32b  --language java
"""
