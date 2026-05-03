"""
main.py — Entry Point
======================

Loads data, creates all components, and runs batch classification.

USAGE (from inside case_study/ directory):

    # Run with defaults from .env:
    python main.py

    # Override LLM provider via CLI:
    python main.py --provider claude --mode conversation
    python main.py --provider openai --model gpt-5.1
    python main.py --provider ollama --model llama3.2:3b

    # Limit number of issues (for testing):
    python main.py --limit 5

    # Resume from a specific issue ID:
    python main.py --start-from 100

    # Custom output file:
    python main.py --output results_claude_main_1437.json

    # Use test repos:
    python main.py --test-repos

    # Debug mode (verbose tool logs):
    python main.py --debug
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure this file can be run directly from its directory
# by adding the parent to sys.path (for imports to work)
sys.path.insert(0, str(Path(__file__).parent))

from config import SystemConfig, load_config
from llm_interface import LLMClient, get_tool_definitions
from tools import ToolExecutor
from classifier import AgenticClassifier


# =====================================================
# DATA LOADING
# =====================================================
# These functions load the CSV, call graph JSON, and
# knowledge base JSON into dicts that the system uses.

def load_issues(config: SystemConfig) -> Dict[str, Dict]:
    """
    Load issues from the unified CSV file.

    Expected CSV columns: id, repo_name, filename, line_number,
    tool_issue_id, source, all_sources, severity, cwe, issue_text, ...

    Args:
        config: SystemConfig with paths.csv_file

    Returns:
        Dict mapping issue_id (str) → row dict
    """
    csv_path = config.paths.csv_file
    if not csv_path.exists():
        print(f"❌ CSV file not found: {csv_path}")
        sys.exit(1)

    issues: Dict[str, Dict] = {}

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            issue_id = str(row.get("id", "")).strip()
            if issue_id:
                issues[issue_id] = dict(row)

    print(f"📂 Loaded {len(issues)} issues from {csv_path.name}")
    return issues


def load_call_graphs(config: SystemConfig) -> Dict[str, Dict]:
    """
    Load call graphs from JSON file.

    The call graph file maps issue_id → {
        "repo_name": "...",
        "function_name": "...",
        "status": "success",
        "call_graph_context": {
            "callers": [...],
            "callees": [...]
        }
    }

    Args:
        config: SystemConfig with paths.callgraph_file

    Returns:
        Dict mapping issue_id → call graph data
    """
    cg_path = config.paths.callgraph_file
    if not cg_path.exists():
        print(f"⚠️  Call graph file not found: {cg_path}")
        print("   GET_SUBGRAPH and GET_PREDECESSOR tools will not work.")
        return {}

    try:
        with open(cg_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # The call graph JSON can be either:
        #   - A list of objects, each with "issue_id" key (our format)
        #   - A dict mapping issue_id → call graph data
        if isinstance(data, list):
            # Convert list → dict keyed by issue_id
            call_graphs = {
                str(item["issue_id"]): item
                for item in data
                if "issue_id" in item
            }
        elif isinstance(data, dict):
            # Already a dict — normalize keys to strings
            call_graphs = {str(k): v for k, v in data.items()}
        else:
            print(f"⚠️  Unexpected call graph format: {type(data)}")
            return {}

        print(f"📂 Loaded {len(call_graphs)} call graphs from {cg_path.name}")
        return call_graphs
    except Exception as e:
        print(f"⚠️  Error loading call graphs: {e}")
        return {}


# =====================================================
# BATCH PROCESSING
# =====================================================

def classify_all(
    classifier: AgenticClassifier,
    issues: Dict[str, Dict],
    output_file: Path,
    limit: Optional[int] = None,
    start_from: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Classify all issues in batch, saving results incrementally.

    Saves after every issue so no progress is lost on crash.

    Args:
        classifier:  AgenticClassifier instance
        issues:      Dict of all issues
        output_file: Path to write JSON results
        limit:       Max issues to process (None = all)
        start_from:  Start from this issue ID (skip earlier ones)

    Returns:
        List of result dicts
    """
    # Sort issue IDs numerically
    sorted_ids = sorted(issues.keys(), key=lambda x: int(x) if x.isdigit() else 0)

    # Apply start_from filter
    if start_from is not None:
        start_str = str(start_from)
        try:
            idx = sorted_ids.index(start_str)
            sorted_ids = sorted_ids[idx:]
            print(f"📍 Starting from issue #{start_from} ({len(sorted_ids)} remaining)")
        except ValueError:
            print(f"⚠️  Issue #{start_from} not found, starting from beginning")

    # Apply limit
    if limit:
        sorted_ids = sorted_ids[:limit]
        print(f"📍 Limiting to {limit} issues")

    # Load existing results (for resume support)
    results = _load_existing_results(output_file)
    done_ids = {r["issue_id"] for r in results}
    print(f"📍 Already completed: {len(done_ids)} issues")

    # Process each issue
    total = len(sorted_ids)
    for i, issue_id in enumerate(sorted_ids):
        if issue_id in done_ids:
            continue  # Already processed (resume)

        print(f"\n{'='*60}")
        print(f"[{i+1}/{total}] Issue #{issue_id}")
        print(f"{'='*60}")

        start_time = time.time()
        result = classifier.classify_issue(issue_id)
        elapsed = time.time() - start_time
        result["processing_time_sec"] = round(elapsed, 2)

        results.append(result)

        # Save incrementally (no progress lost on crash)
        _save_results(results, output_file)

        # Brief status
        cls = result.get("classification", "?")
        iters = result.get("num_iterations", 0)
        print(f"  → {cls} ({iters} iterations, {elapsed:.1f}s)")

    return results


def _load_existing_results(output_file: Path) -> List[Dict]:
    """Load existing results from output file (for resume support)."""
    if output_file.exists():
        try:
            with open(output_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, Exception):
            pass
    return []


def _save_results(results: List[Dict], output_file: Path) -> None:
    """Save results to JSON file (overwrites)."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)


# =====================================================
# SUMMARY
# =====================================================

def print_summary(results: List[Dict], config: SystemConfig) -> None:
    """
    Print a summary of classification results.

    Shows:
      - Total counts by classification (TP, FP, NON_ACTIONABLE, ERROR)
      - Average iterations and tool usage
      - Per-tool breakdown
    """
    if not results:
        print("\n📊 No results to summarize.")
        return

    total = len(results)
    labels = Counter(r.get("classification", "?") for r in results)
    successes = [r for r in results if r.get("success")]

    print(f"\n{'='*60}")
    print(f"📊 RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"  LLM:    {config.llm.provider} / {config.llm.model}")
    print(f"  Temp:   {config.llm.temperature}")
    print(f"  Mode:   {config.mode}")
    print(f"  Repos:  {'TEST' if config.paths.use_test_repos else 'MAIN'}")
    print(f"  Total:  {total}")
    print()

    # Classification breakdown
    for label in ("TP", "FP", "NON_ACTIONABLE", "ERROR"):
        count = labels.get(label, 0)
        pct = (count / total * 100) if total > 0 else 0
        print(f"  {label:8s}: {count:4d} ({pct:5.1f}%)")

    # Average iterations
    if successes:
        avg_iters = sum(r.get("num_iterations", 0) for r in successes) / len(successes)
        print(f"\n  Avg iterations: {avg_iters:.1f}")

        # Average tool calls
        all_tool_counts = Counter()
        for r in successes:
            for tool, count in r.get("tool_call_counts", {}).items():
                all_tool_counts[tool] += count

        total_calls = sum(all_tool_counts.values())
        if total_calls:
            print(f"  Total tool calls: {total_calls}")
            print(f"  Avg calls/issue: {total_calls / len(successes):.1f}")
            print(f"\n  Tool breakdown:")
            for tool, count in all_tool_counts.most_common():
                print(f"    {tool:20s}: {count:4d}")

    print(f"{'='*60}")


# =====================================================
# CLI ENTRY POINT
# =====================================================

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments (overrides .env settings)."""
    parser = argparse.ArgumentParser(
        description="Agentic LLM System for Crypto Misuse Classification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                      # Use .env defaults
  python main.py --provider claude --mode conversation # Claude conversation mode
  python main.py --provider openai --model gpt-5.1    # GPT-5.1
  python main.py --provider ollama --model llama3.2:3b # Local Llama
  python main.py --test-repos --limit 10               # Test repos, first 10
  python main.py --start-from 500                      # Resume from issue 500
        """,
    )

    # LLM settings (override .env)
    parser.add_argument("--provider", choices=["claude", "openai", "ollama"],
                        help="LLM provider (overrides LLM_PROVIDER in .env)")
    parser.add_argument("--model", help="Model name (overrides ANTHROPIC_MODEL / OPENAI_MODEL / OLLAMA_MODEL)")
    parser.add_argument("--mode", choices=["stateless", "conversation"],
                        help="Classification mode (overrides MODE in .env)")

    # Data selection
    parser.add_argument("--test-repos", action="store_true",
                        help="Use test repos (overrides USE_TEST_REPOS in .env)")
    parser.add_argument("--main-repos", action="store_true",
                        help="Use main repos (overrides USE_TEST_REPOS in .env)")

    # Processing control
    parser.add_argument("--limit", type=int, help="Max issues to process")
    parser.add_argument("--start-from", type=int, help="Start from this issue ID")
    parser.add_argument("--output", help="Output JSON file path")

    # Language selection (Python repos vs Java repos)
    parser.add_argument("--language", choices=["python", "java"], default=None,
                        help="Target language: 'python' or 'java'. Controls file extensions, "
                             "function detection, Semgrep rulesets, CodeQL query suites. "
                             "(overrides LANGUAGE in .env, default: python)")

    # Misc
    parser.add_argument("--debug", action="store_true", help="Verbose debug output")

    return parser.parse_args()


def main():
    """
    Main entry point.

    Flow:
        1. Parse CLI args
        2. Load config (.env + CLI overrides)
        3. Load data (CSV, call graphs, knowledge base)
        4. Create LLM client, tool executor, classifier
        5. Run batch classification
        6. Print summary
    """
    args = parse_args()

    # --- Load config (reload after env overrides) ---
    # Apply env overrides from CLI args BEFORE loading config
    if args.provider:
        import os
        os.environ["LLM_PROVIDER"] = args.provider
    if args.test_repos:
        import os
        os.environ["USE_TEST_REPOS"] = "true"
    elif args.main_repos:
        import os
        os.environ["USE_TEST_REPOS"] = "false"
    if args.language:
        import os
        os.environ["LANGUAGE"] = args.language

    config = load_config()

    # Apply remaining CLI overrides
    if args.model:
        config.llm.model = args.model
    if args.mode:
        config.mode = args.mode
    if args.debug:
        config.debug = True
    if args.language:
        config.language = args.language

    # --- Print config ---
    print(f"\n{'='*60}")
    print(f"🚀 Agentic Crypto Misuse Classifier")
    print(f"{'='*60}")
    print(f"  Provider:    {config.llm.provider}")
    print(f"  Model:       {config.llm.model}")
    print(f"  Temperature: {config.llm.temperature}")
    print(f"  Mode:        {config.mode}")
    print(f"  Language:    {config.language}")
    print(f"  Repos:       {'TEST' if config.paths.use_test_repos else 'MAIN'}")
    print(f"  Max iter:    {config.max_iterations}")
    print(f"  Tools:       9 (all investigation tools active)")
    tool_defs = get_tool_definitions()
    print(f"  Tool calling: native API ({len(tool_defs)} investigation tools)")
    print(f"  Debug:       {config.debug}")
    print(f"{'='*60}\n")

    # --- Load data ---
    issues = load_issues(config)
    call_graphs = load_call_graphs(config)

    # --- Create components ---
    llm = LLMClient(config.llm)
    tools = ToolExecutor(config, call_graphs)
    classifier = AgenticClassifier(config, llm, tools, issues, call_graphs)

    # --- Determine output file ---
    if args.output:
        output_file = Path(args.output)
    else:
        # Auto-generate: results_{provider}_{dataset}_{count}.json
        # e.g., results_claude_main_1437.json, results_ollama_test_947.json
        dataset = "test" if config.paths.use_test_repos else "main"
        count = len(issues)
        # Clean model name for filename (e.g., "claude-sonnet-4-5-20250929" → "claude")
        provider_short = config.llm.provider
        if provider_short == "ollama":
            provider_short = config.llm.model.split(":")[0]  # e.g., "llama3.2"
        output_file = config.paths.data_dir / f"results_{provider_short}_{dataset}_{count}.json"

    print(f"📄 Output: {output_file}")

    # --- Run classification ---
    results = classify_all(
        classifier=classifier,
        issues=issues,
        output_file=output_file,
        limit=args.limit,
        start_from=args.start_from,
    )

    # --- Print summary ---
    print_summary(results, config)

    print(f"\n✅ Done! Results saved to: {output_file}")


if __name__ == "__main__":
    main()

