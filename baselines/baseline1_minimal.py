#!/usr/bin/env python3
"""
BASELINE 1: Minimal Prompt + CSV Snippet
=========================================
Tests: How well does the LLM classify with just basic definitions and code?
No decision framework, no examples, no guidance.
 CSV snippet only (whatever the CSV provides)
Taxonomy: TP / FP / NON_ACTIONABLE
Context:
"""

import csv
import json
import re
import time
from typing import List, Dict, Optional

# ----------------------------
# MINIMAL SYSTEM PROMPT
# ----------------------------

STRICT_SYSTEM = """You are a security code reviewer.
Output STRICT JSON ONLY (no prose, no code fences). Schema:
{"classification": "TP" or "FP" or "NON_ACTIONABLE",
 "confidence": "HIGH" or "MEDIUM" or "LOW",
 "reasoning": "Concise explanation",
 "context_indicators": ["list","of","key","factors"],
 "recommendation": "One actionable next step"}

Classification definitions:
- TP (True Positive): Real exploitable cryptographic vulnerability that could be leveraged by an attacker
- FP (False Positive): Not a real vulnerability (includes test code, non-security usage, or mitigated issues)
- NON_ACTIONABLE: Real cryptographic weakness, but the developer cannot fix it without breaking functionality (e.g., a protocol or specification mandates the insecure algorithm)
"""

# ----------------------------
# MINIMAL USER PROMPT
# ----------------------------

BASELINE1_PROMPT = """Analyze this potential cryptographic misuse.

- Repository: {repo_name}
- File: {filename}
- Line: {line_number}
- Severity: {severity}
- Detected by: {all_sources}
- Issue: {issue_text}

**Code:**
```
{code}
```

Classify as TP, FP, or NON_ACTIONABLE. Respond in JSON."""

# ----------------------------
# Utilities
# ----------------------------

def extract_json(text: str) -> dict:
    """Parse JSON from a model reply."""
    if not text:
        raise ValueError("Empty response from model")
    s = text.strip()

    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    m = re.search(r"\{.*\}", s, flags=re.DOTALL)
    if m:
        chunk = m.group(0)
        obj = json.loads(chunk)
        if isinstance(obj, dict):
            return obj

    raise ValueError("Could not parse JSON from model response")


def create_llm_prompt(issue: Dict) -> str:
    """Create minimal prompt from one issue row."""
    return BASELINE1_PROMPT.format(
        repo_name=issue.get('repo_name', 'unknown'),
        filename=issue.get('filename', 'unknown'),
        line_number=issue.get('line_number', '?'),
        severity=issue.get('severity', 'UNKNOWN'),
        all_sources=issue.get('all_sources', issue.get('detected_by', 'unknown')),
        issue_text=issue.get('issue_text', issue.get('message', 'unknown')),
        code=issue.get('code', issue.get('code_snippet', 'No code snippet available')),
    )


def load_issues(csv_file: str, limit: Optional[int] = None) -> List[Dict]:
    """Load issues from CSV."""
    with open(csv_file, 'r', newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        issues = list(reader)
    if limit:
        issues = issues[:limit]
    return issues


def save_results(results: List[Dict], output_file: str):
    """Save results to JSON."""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"Saved {len(results)} results to {output_file}")


# ----------------------------
# LLM Backends
# ----------------------------

def analyze_with_claude(prompt: str, api_key: Optional[str] = None, model_name: Optional[str] = None) -> Optional[Dict]:
    """Analyze using Anthropic Claude."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        model = model_name or "claude-sonnet-4-5-20250929"

        msg = client.messages.create(
            model=model,
            max_tokens=800,
            temperature=0,
            system=STRICT_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )

        parts = []
        for block in (msg.content or []):
            if hasattr(block, "text"):
                parts.append(block.text)
            elif isinstance(block, dict) and "text" in block:
                parts.append(block["text"])
        raw = "\n".join([p for p in parts if p]).strip()

        result = extract_json(raw)
        result["llm"] = model
        result["_raw"] = raw
        return result

    except ImportError:
        print("Anthropic library not installed. Run: pip install anthropic")
        return None
    except Exception as e:
        print(f"Error with Claude: {e}")
        return None


def analyze_with_openai_gpt(prompt: str, api_key: Optional[str] = None, model_name: Optional[str] = None, reasoning_effort: Optional[str] = None) -> Optional[Dict]:
    """Analyze using OpenAI GPT models (supports GPT-4o, o1, GPT-5.1)."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key) if api_key else OpenAI()
        chosen = model_name or "gpt-4o-mini"

        is_o1_model = chosen.startswith('o1')
        is_gpt5_model = chosen.startswith('gpt-5')

        if is_o1_model:
            resp = client.chat.completions.create(
                model=chosen,
                messages=[
                    {"role": "user", "content": f"{STRICT_SYSTEM}\n\n{prompt}"},
                ],
            )
        elif is_gpt5_model:
            # GPT-5.x uses reasoning_effort instead of max_tokens
            effort = reasoning_effort or 'medium'
            params = {
                "model": chosen,
                "messages": [
                    {"role": "system", "content": STRICT_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                # "temperature": 0,
                "reasoning_effort": effort,
            }
            resp = client.chat.completions.create(**params)
        else:
            resp = client.chat.completions.create(
                model=chosen,
                messages=[
                    {"role": "system", "content": STRICT_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
                max_tokens=800,
            )

        raw = resp.choices[0].message.content
        result = extract_json(raw)
        result["llm"] = chosen
        result["_raw"] = raw
        return result

    except ImportError:
        print("OpenAI library not installed. Run: pip install --upgrade openai")
        return None
    except Exception as e:
        print(f"Error with GPT: {e}")
        return None


def analyze_with_ollama(prompt: str, model_name: str = "llama3.1:8b", base_url: str = "http://localhost:11434") -> Optional[Dict]:
    """Analyze using local Ollama models."""
    try:
        from openai import OpenAI
        client = OpenAI(
            base_url=f"{base_url}/v1",
            api_key="ollama",
        )

        resp = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": STRICT_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            max_completion_tokens=800,
            temperature=0,
            response_format={"type": "json_object"},
        )

        raw = resp.choices[0].message.content
        result = extract_json(raw)
        result["llm"] = model_name
        result["_raw"] = raw
        return result

    except ImportError:
        print("OpenAI library not installed. Run: pip install --upgrade openai")
        return None
    except Exception as e:
        print(f"Error with Ollama ({model_name}): {e}")
        return None


# ----------------------------
# Batch Runner
# ----------------------------

def batch_analyze(
    csv_file: str,
    output_file: str,
    llm: str = 'claude',
    limit: int = 10,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    sleep: float = 0.2,
    ollama_url: str = "http://localhost:11434",
    reasoning_effort: Optional[str] = None,
):
    """Batch analyze issues."""
    print("=" * 80)
    print("BASELINE 1: Minimal Prompt + CSV Snippet")
    print("=" * 80)

    issues = load_issues(csv_file, limit=limit)
    print(f"Loaded {len(issues)} issues. Analyzing with {llm.upper()}...\n")

    results: List[Dict] = []

    for i, issue in enumerate(issues, 1):
        fname = issue.get('filename', 'unknown')
        lnum = issue.get('line_number', '?')
        print(f"[{i}/{len(issues)}] {fname}:{lnum}")

        prompt = create_llm_prompt(issue)

        if llm == 'gpt':
            analysis = analyze_with_openai_gpt(prompt, api_key=api_key, model_name=model, reasoning_effort=reasoning_effort)
        elif llm == 'claude':
            analysis = analyze_with_claude(prompt, api_key=api_key, model_name=model)
        elif llm == 'ollama':
            analysis = analyze_with_ollama(prompt, model_name=model or "llama3.1:8b", base_url=ollama_url)
        else:
            print(f"  Unknown LLM: {llm}")
            continue

        if analysis:
            result = {
                'issue_id': issue.get('id'),
                'repo_name': issue.get('repo_name', 'unknown'),
                'filename': fname,
                'line_number': lnum,
                'original_severity': issue.get('severity', 'UNKNOWN'),
                'issue_text': issue.get('issue_text', issue.get('message', '')),
                'llm_analysis': analysis,
            }
            results.append(result)
            print(f"  → {analysis.get('classification')} ({analysis.get('confidence')})")
        else:
            print("  → ⚠️  No analysis")

        if i % 10 == 0:
            save_results(results, output_file)

        time.sleep(max(0.0, sleep))

    save_results(results, output_file)

    # Summary
    print("\n" + "=" * 80)
    print("BASELINE 1 SUMMARY")
    print("=" * 80)
    total = len(results)
    if total > 0:
        tp = sum(1 for r in results if r['llm_analysis'].get('classification') == 'TP')
        fp = sum(1 for r in results if r['llm_analysis'].get('classification') == 'FP')
        na = sum(1 for r in results if r['llm_analysis'].get('classification') == 'NON_ACTIONABLE')
        high = sum(1 for r in results if r['llm_analysis'].get('confidence') == 'HIGH')
        print(f"Total analyzed: {total}")
        print(f"  TP:      {tp} ({tp*100/total:.1f}%)")
        print(f"  FP:      {fp} ({fp*100/total:.1f}%)")
        print(f"  NA:      {na} ({na*100/total:.1f}%)")
        print(f"  High confidence: {high} ({high*100/total:.1f}%)")
    else:
        print("⚠️ No results")
    print("=" * 80)


# ----------------------------
# CLI
# ----------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Baseline 1: Minimal prompt + CSV snippet")
    parser.add_argument('--input', type=str, default='union_crypto_issues_usercode.csv')
    parser.add_argument('--output', type=str, default='baseline1_results.json')
    parser.add_argument('--llm', type=str, choices=['gpt', 'claude', 'ollama'], default='claude')
    parser.add_argument('--limit', type=int, default=None,
                        help='Cap rows processed; default=None means process all rows in CSV')
    parser.add_argument('--api-key', type=str, default=None)
    parser.add_argument('--model', type=str, default=None)
    parser.add_argument('--sleep', type=float, default=0.2)
    parser.add_argument('--ollama-url', type=str, default='http://localhost:11434')
    parser.add_argument('--reasoning-effort', type=str, default=None,
                        choices=['none', 'low', 'medium', 'high'],
                        help='Reasoning effort for GPT-5.x models')

    args = parser.parse_args()

    batch_analyze(
        csv_file=args.input,
        output_file=args.output,
        llm=args.llm,
        limit=args.limit,
        api_key=args.api_key,
        model=args.model,
        sleep=args.sleep,
        ollama_url=args.ollama_url,
        reasoning_effort=args.reasoning_effort,
    )

