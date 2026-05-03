#!/usr/bin/env python3
"""
Filter Semgrep results to extract crypto-specific issues only.
Similar to filter_bandit_crypto.py but for Semgrep output.

Usage:
    python filter_semgrep_crypto.py --semgrep-dir ./semgrep_results --db crypto_usage.db [--rebuild]
"""

import argparse
import json
import sqlite3
import re
from pathlib import Path
from datetime import datetime


# Crypto-specific patterns to INCLUDE
CRYPTO_PATTERNS = [
    # Hash algorithms
    r'insecure-hash-algorithm',
    r'md5-used-as-password',
    r'sha\d+-hash',
    
    # Ciphers and encryption
    r'insecure-cipher-algorithm',
    r'insufficient.*key-size',
    r'weak-encryption',
    r'insecure-cipher-mode',
    
    # SSL/TLS
    r'weak-ssl',
    r'disabled-cert-validation',
    r'unverified-ssl',
    r'no-set-ciphers',
    r'ssl-wrap-socket',
    r'bypass-tls',
    
    # Random
    r'insecure-random',
    r'weak-prng',
    
    # Key management
    r'hardcoded.*key',
    r'weak.*key',
]

# Patterns to EXCLUDE (non-crypto security issues)
EXCLUDE_PATTERNS = [
    r'pickle',
    r'cPickle',
    r'marshal',
    r'yaml',
    r'detected-private-key',  # Hardcoded secrets, not crypto misuse
    r'detected.*api-key',
    r'detected.*access-key',
    r'detected.*token',
    r'detected.*password',
    r'hardcoded-config',
    r'path-traversal',
    r'sql-injection',
    r'command-injection',
    r'xss',
    r'csrf',
]


def is_crypto_issue(check_id):
    """Determine if a Semgrep check_id is crypto-related."""
    check_id_lower = check_id.lower()
    
    # Exclude non-crypto issues first
    for pattern in EXCLUDE_PATTERNS:
        if re.search(pattern, check_id_lower):
            return False
    
    # Check if it matches crypto patterns
    for pattern in CRYPTO_PATTERNS:
        if re.search(pattern, check_id_lower):
            return True
    
    return False


def create_filtered_table(conn):
    """Create table for filtered Semgrep results."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS semgrep_crypto_filtered (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_name TEXT,
            check_id TEXT,
            severity TEXT,
            filename TEXT,
            line_number INTEGER,
            code TEXT,
            issue_text TEXT,
            confidence TEXT,
            cwe TEXT,
            manual_review TEXT,
            notes TEXT,
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_semgrep_crypto_repo 
        ON semgrep_crypto_filtered(repo_name)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_semgrep_crypto_check 
        ON semgrep_crypto_filtered(check_id)
    """)
    conn.commit()


def extract_repo_name(file_path):
    """Extract repo name from Semgrep JSON filename or result path."""
    # Try to get from the path field (e.g., "repos/owner_repo/file.py")
    path_obj = Path(file_path)
    if 'repos/' in file_path:
        parts = file_path.split('repos/')
        if len(parts) > 1:
            repo_part = parts[1].split('/')[0]
            return repo_part
    return "unknown"


def get_code_snippet(file_path, start_line, end_line, max_lines=5):
    """Extract code snippet from file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            # Get context: 2 lines before, the issue, 2 lines after
            context_start = max(0, start_line - 3)
            context_end = min(len(lines), end_line + 2)
            snippet = ''.join(lines[context_start:context_end])
            return snippet[:500]  # Limit to 500 chars
    except Exception as e:
        return f"[Could not read file: {e}]"


def process_semgrep_file(json_path, conn):
    """Process a single Semgrep JSON file and insert crypto issues."""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"  ⚠️  Error reading {json_path.name}: {e}")
        return 0
    
    results = data.get('results', [])
    crypto_count = 0
    
    for result in results:
        check_id = result.get('check_id', '')
        
        # Filter for crypto-related issues
        if not is_crypto_issue(check_id):
            continue
        
        # Extract fields
        path = result.get('path', '')
        repo_name = extract_repo_name(path)
        
        start = result.get('start', {})
        end = result.get('end', {})
        line_number = start.get('line', 0)
        end_line = end.get('line', line_number)
        
        extra = result.get('extra', {})
        message = extra.get('message', '')
        severity = extra.get('severity', 'WARNING')
        metadata = extra.get('metadata', {})
        
        confidence = metadata.get('confidence', 'UNKNOWN')
        cwe_list = metadata.get('cwe', [])
        cwe = ', '.join(cwe_list) if cwe_list else ''
        
        # Get code snippet
        code = get_code_snippet(path, line_number, end_line)
        
        # Insert into database
        conn.execute("""
            INSERT INTO semgrep_crypto_filtered 
            (repo_name, check_id, severity, filename, line_number, code, 
             issue_text, confidence, cwe, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            repo_name,
            check_id,
            severity,
            path,
            line_number,
            code,
            message,
            confidence,
            cwe,
            datetime.utcnow().isoformat()
        ))
        
        crypto_count += 1
    
    return crypto_count


def main():
    parser = argparse.ArgumentParser(description="Filter Semgrep results for crypto issues")
    parser.add_argument("--semgrep-dir", default="./semgrep_results", 
                        help="Directory with Semgrep JSON files")
    parser.add_argument("--db", default="crypto_usage.db", 
                        help="Database path")
    parser.add_argument("--rebuild", action="store_true",
                        help="Drop and rebuild the filtered table")
    args = parser.parse_args()
    
    semgrep_dir = Path(args.semgrep_dir)
    if not semgrep_dir.exists():
        print(f"❌ Semgrep directory not found: {semgrep_dir}")
        return
    
    conn = sqlite3.connect(args.db)
    
    # Optionally rebuild table
    if args.rebuild:
        print("🔄 Rebuilding semgrep_crypto_filtered table...")
        conn.execute("DROP TABLE IF EXISTS semgrep_crypto_filtered")
    
    create_filtered_table(conn)
    
    # Process all JSON files
    json_files = list(semgrep_dir.glob("*.json"))
    print(f"📁 Found {len(json_files)} Semgrep result files")
    
    total_issues = 0
    processed_files = 0
    
    for json_path in json_files:
        count = process_semgrep_file(json_path, conn)
        if count > 0:
            processed_files += 1
            total_issues += count
            if processed_files % 100 == 0:
                print(f"  Processed {processed_files} files, {total_issues} crypto issues so far...")
    
    conn.commit()
    
    # Summary statistics
    print("\n" + "="*60)
    print("📊 SEMGREP CRYPTO FILTERING SUMMARY")
    print("="*60)
    print(f"Files processed:      {processed_files}")
    print(f"Total crypto issues:  {total_issues}")
    
    # Breakdown by check_id
    cursor = conn.execute("""
        SELECT check_id, COUNT(*) as count
        FROM semgrep_crypto_filtered
        GROUP BY check_id
        ORDER BY count DESC
        LIMIT 15
    """)
    
    print("\nTop 15 crypto issue types:")
    print("-"*60)
    for check_id, count in cursor:
        short_id = check_id.split('.')[-1] if '.' in check_id else check_id
        print(f"  {count:4d}  {short_id}")
    
    # Breakdown by severity
    cursor = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM semgrep_crypto_filtered
        GROUP BY severity
        ORDER BY count DESC
    """)
    
    print("\nBy severity:")
    print("-"*60)
    for severity, count in cursor:
        print(f"  {severity:<10} {count:4d}")
    
    print("\n✅ Filtered results saved to: semgrep_crypto_filtered table")
    print(f"Database: {args.db}")
    print("="*60)
    
    conn.close()


if __name__ == "__main__":
    main()

