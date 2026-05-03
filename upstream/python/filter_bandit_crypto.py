#!/usr/bin/env python3
"""
Filter Bandit Results for Crypto-Specific Issues Only

Based on NDSS24 paper "Towards Precise Reporting of Cryptographic Misuses"
This script filters out generic security issues and keeps only crypto-library-specific misuses.

Usage:
    python filter_bandit_crypto.py --bandit-dir ./bandit_results --output filtered_results.csv

Date: October 2025
"""

import json
import sqlite3
import argparse
import sys
from pathlib import Path
from collections import defaultdict
import csv


# Crypto-specific Bandit test IDs (based on NDSS24 paper analysis)
CRYPTO_SPECIFIC_TESTS = {
    # Hash functions (Pattern #18 from paper)
    'B303': {
        'name': 'MD5/SHA1 usage',
        'description': 'Use of insecure MD5 or SHA1 hash function',
        'paper_pattern': 'Pattern #18 - collision-prone hash functions',
        'severity': 'MEDIUM',
        'context_critical': True  # Context matters a lot!
    },
    'B324': {
        'name': 'hashlib with insecure functions',
        'description': 'Use of insecure hash functions via hashlib',
        'paper_pattern': 'Pattern #18',
        'severity': 'MEDIUM',
        'context_critical': True
    },
    
    # Ciphers and modes (Pattern #15 from paper)
    'B304': {
        'name': 'Insecure cipher usage',
        'description': 'Use of insecure cipher algorithms (DES, RC4, etc.)',
        'paper_pattern': 'Pattern #15',
        'severity': 'HIGH',
        'context_critical': False
    },
    'B305': {
        'name': 'Insecure cipher modes',
        'description': 'Use of insecure cipher modes (ECB, etc.)',
        'paper_pattern': 'Pattern #15 - AES-ECB context matters',
        'severity': 'MEDIUM',
        'context_critical': True  # ECB can be OK when implementing other modes!
    },
    
    # SSL/TLS (Pattern #10 from paper)
    'B323': {
        'name': 'Unverified SSL/TLS context',
        'description': 'SSL/TLS certificate verification disabled',
        'paper_pattern': 'Pattern #10 - MITM issues',
        'severity': 'HIGH',
        'context_critical': False
    },
    'B501': {
        'name': 'Request with verify=False',
        'description': 'requests.get/post with verify=False',
        'paper_pattern': 'Pattern #10',
        'severity': 'HIGH',
        'context_critical': True  # localhost/debug might be OK
    },
    'B502': {
        'name': 'SSL with bad defaults',
        'description': 'SSL/TLS with insecure default settings',
        'paper_pattern': 'Pattern #10',
        'severity': 'HIGH',
        'context_critical': False
    },
    'B503': {
        'name': 'SSL with bad ciphers',
        'description': 'SSL/TLS with weak cipher suites',
        'paper_pattern': 'Pattern #10',
        'severity': 'HIGH',
        'context_critical': False
    },
    'B504': {
        'name': 'SSL with bad TLS version',
        'description': 'SSL/TLS with insecure protocol version',
        'paper_pattern': 'Pattern #10',
        'severity': 'HIGH',
        'context_critical': False
    },
    
    # Key management
    'B505': {
        'name': 'Weak cryptographic key',
        'description': 'Cryptographic key with insufficient length',
        'paper_pattern': 'Pattern #7 - key size issues',
        'severity': 'HIGH',
        'context_critical': False
    },
    
    # # Deprecated libraries
    # 'B413': {
    #     'name': 'PyCrypto usage (deprecated)',
    #     'description': 'Use of deprecated PyCrypto library',
    #     'paper_pattern': 'N/A - library deprecation',
    #     'severity': 'HIGH',
    #     'context_critical': False
    # },
    
    # Random number generation (Pattern #16 from paper)
    'B311': {
        'name': 'Pseudo-random generators',
        'description': 'Use of random module for security/cryptography',
        'paper_pattern': 'Pattern #16 - non-CSPRNG usage',
        'severity': 'LOW',
        'context_critical': True  # Can be OK for non-security uses!
    },
}

# Generic security tests to EXCLUDE (not crypto-library misuse)
GENERIC_TESTS_TO_EXCLUDE = {
    # Password/token storage (NOT crypto-library misuse)
    'B105': 'Hardcoded password string',
    'B106': 'Hardcoded password func arg',
    'B107': 'Hardcoded password default',
    
    # Deserialization (NOT crypto)
    'B301': 'Pickle usage',
    'B302': 'Pickle with shell',
    'B506': 'YAML load',
    
    # Import warnings (NOT misuse)
    'B403': 'Import pickle',
    'B404': 'Import subprocess',
    'B405': 'Import xml.etree',
    'B406': 'Import xml.sax',
    'B407': 'Import xml.expat',
    'B408': 'Import xml.minidom',
    'B409': 'Import xml.pulldom',
    'B410': 'Import lxml',
    'B411': 'Import xmlrpc',
    'B412': 'Import httpoxy',
    
    # Library deprecation (NOT crypto misuse - just old library)
    'B413': 'PyCrypto usage (deprecated library, not misuse)',
}

# Context indicators (for automated flagging - not perfect, but helpful)
SECURITY_CONTEXT_KEYWORDS = [
    'password', 'secret', 'key', 'token', 'auth', 'credential',
    'encrypt', 'decrypt', 'cipher', 'signature', 'certificate',
    'private', 'sensitive', 'secure', 'verify', 'validate'
]

NON_SECURITY_CONTEXT_KEYWORDS = [
    'cache', 'hash', 'index', 'lookup', 'etag', 'checksum',
    'test', 'debug', 'localhost', 'example', 'demo', 'mock',
    'animation', 'random', 'shuffle', 'placeholder'
]


def read_bandit_json(json_path):
    """Read a Bandit JSON result file."""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError as e:
        print(f"⚠️  JSON decode error in {json_path}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"⚠️  Error reading {json_path}: {e}", file=sys.stderr)
        return None


def is_crypto_specific(issue):
    """Check if a Bandit issue is crypto-specific."""
    test_id = issue.get('test_id', '')
    
    # Check if it's in our crypto-specific list
    if test_id in CRYPTO_SPECIFIC_TESTS:
        return True
    
    # Explicitly exclude generic tests
    if test_id in GENERIC_TESTS_TO_EXCLUDE:
        return False
    
    # For unknown test IDs, check if it's crypto-related based on text
    issue_text = issue.get('issue_text', '').lower()
    test_name = issue.get('test_name', '').lower()
    
    crypto_keywords = ['crypto', 'cipher', 'hash', 'ssl', 'tls', 'encrypt', 'decrypt']
    
    if any(keyword in issue_text or keyword in test_name for keyword in crypto_keywords):
        return True
    
    return False


def guess_context(issue):
    """
    Attempt to guess the context of an issue (security vs non-security).
    This is NOT perfect - manual review is still needed!
    But it helps flag potential false positives.
    """
    filename = issue.get('filename', '').lower()
    code = issue.get('code', '').lower()
    issue_text = issue.get('issue_text', '').lower()
    
    combined_text = f"{filename} {code} {issue_text}"
    
    # Check for security context indicators
    security_score = sum(1 for kw in SECURITY_CONTEXT_KEYWORDS if kw in combined_text)
    non_security_score = sum(1 for kw in NON_SECURITY_CONTEXT_KEYWORDS if kw in combined_text)
    
    if non_security_score > security_score:
        return 'LIKELY_NON_SECURITY'
    elif security_score > 0:
        return 'LIKELY_SECURITY'
    else:
        return 'UNKNOWN'


def extract_repo_name(json_filename):
    """Extract repo name from Bandit JSON filename."""
    # Format: owner_reponame_bandit.json
    name = Path(json_filename).stem
    if name.endswith('_bandit'):
        name = name[:-7]  # Remove '_bandit'
    return name


def process_bandit_results(bandit_dir):
    """Process all Bandit JSON files and extract crypto-specific issues."""
    bandit_path = Path(bandit_dir)
    
    if not bandit_path.exists():
        print(f"❌ Error: Directory {bandit_dir} does not exist!", file=sys.stderr)
        sys.exit(1)
    
    json_files = list(bandit_path.glob('*_bandit.json'))
    
    if not json_files:
        print(f"❌ Error: No *_bandit.json files found in {bandit_dir}!", file=sys.stderr)
        sys.exit(1)
    
    print(f"📁 Found {len(json_files)} Bandit result files")
    
    all_issues = []
    stats = {
        'total_repos': 0,
        'total_issues': 0,
        'crypto_issues': 0,
        'generic_issues': 0,
        'by_test_id': defaultdict(int),
        'by_severity': defaultdict(int),
        'by_context': defaultdict(int),
    }
    
    for json_file in json_files:
        repo_name = extract_repo_name(json_file.name)
        data = read_bandit_json(json_file)
        
        if not data:
            continue
        
        stats['total_repos'] += 1
        
        results = data.get('results', [])
        stats['total_issues'] += len(results)
        
        for issue in results:
            test_id = issue.get('test_id', 'UNKNOWN')
            severity = issue.get('issue_severity', 'UNKNOWN')
            
            # Check if crypto-specific
            if is_crypto_specific(issue):
                stats['crypto_issues'] += 1
                stats['by_test_id'][test_id] += 1
                stats['by_severity'][severity] += 1
                
                # Guess context
                context_guess = guess_context(issue)
                stats['by_context'][context_guess] += 1
                
                # Add repo name and context guess to issue
                issue['repo_name'] = repo_name
                issue['context_guess'] = context_guess
                issue['test_info'] = CRYPTO_SPECIFIC_TESTS.get(test_id, {})
                
                all_issues.append(issue)
            else:
                stats['generic_issues'] += 1
    
    return all_issues, stats


def save_to_csv(issues, output_path):
    """Save filtered issues to CSV for manual review."""
    if not issues:
        print("⚠️  No crypto-specific issues found!")
        return
    
    fieldnames = [
        'repo_name',
        'test_id',
        'test_name',
        'severity',
        'confidence',
        'filename',
        'line_number',
        'line_range',
        'code',
        'issue_text',
        'context_guess',
        'paper_pattern',
        'manual_review',
        'real_misuse',
        'notes'
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for issue in issues:
            test_info = issue.get('test_info', {})
            
            line_range = issue.get('line_range', [])
            if len(line_range) >= 2:
                line_range_str = f"{line_range[0]}-{line_range[1]}"
            else:
                line_range_str = str(issue.get('line_number', ''))
            
            row = {
                'repo_name': issue.get('repo_name', ''),
                'test_id': issue.get('test_id', ''),
                'test_name': issue.get('test_name', ''),
                'severity': issue.get('issue_severity', ''),
                'confidence': issue.get('issue_confidence', ''),
                'filename': issue.get('filename', ''),
                'line_number': issue.get('line_number', ''),
                'line_range': line_range_str,
                'code': issue.get('code', '').strip(),
                'issue_text': issue.get('issue_text', ''),
                'context_guess': issue.get('context_guess', ''),
                'paper_pattern': test_info.get('paper_pattern', ''),
                'manual_review': 'TODO',  # For you to fill in
                'real_misuse': '',  # For you to fill in: YES/NO
                'notes': ''  # For your reasoning
            }
            
            writer.writerow(row)
    
    print(f"✅ Saved {len(issues)} crypto-specific issues to {output_path}")


def save_to_database(issues, db_path):
    """Save filtered issues to SQLite database."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Create table for filtered results
    cur.execute("""
        CREATE TABLE IF NOT EXISTS bandit_crypto_filtered (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_name TEXT,
            test_id TEXT,
            test_name TEXT,
            severity TEXT,
            confidence TEXT,
            filename TEXT,
            line_number INTEGER,
            line_range_start INTEGER,
            line_range_end INTEGER,
            code TEXT,
            issue_text TEXT,
            context_guess TEXT,
            paper_pattern TEXT,
            manual_review TEXT DEFAULT 'TODO',
            real_misuse TEXT DEFAULT NULL,
            notes TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Insert issues
    for issue in issues:
        test_info = issue.get('test_info', {})
        line_range = issue.get('line_range', [None, None])
        
        cur.execute("""
            INSERT INTO bandit_crypto_filtered 
            (repo_name, test_id, test_name, severity, confidence, filename, 
             line_number, line_range_start, line_range_end, code, issue_text, 
             context_guess, paper_pattern)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            issue.get('repo_name', ''),
            issue.get('test_id', ''),
            issue.get('test_name', ''),
            issue.get('issue_severity', ''),
            issue.get('issue_confidence', ''),
            issue.get('filename', ''),
            issue.get('line_number', 0),
            line_range[0] if len(line_range) > 0 else None,
            line_range[1] if len(line_range) > 1 else None,
            issue.get('code', ''),
            issue.get('issue_text', ''),
            issue.get('context_guess', ''),
            test_info.get('paper_pattern', '')
        ))
    
    conn.commit()
    conn.close()
    
    print(f"✅ Saved {len(issues)} issues to database: {db_path}")


def print_summary(stats):
    """Print summary statistics."""
    print("\n" + "="*70)
    print("📊 FILTERING SUMMARY")
    print("="*70)
    
    print(f"\n📦 Total Repos Scanned: {stats['total_repos']}")
    print(f"🔍 Total Issues Found: {stats['total_issues']}")
    print(f"🔐 Crypto-Specific Issues: {stats['crypto_issues']} ({stats['crypto_issues']/max(stats['total_issues'], 1)*100:.1f}%)")
    print(f"🔒 Generic Security Issues: {stats['generic_issues']} (excluded)")
    
    print(f"\n📋 Crypto Issues by Test ID:")
    for test_id in sorted(stats['by_test_id'].keys()):
        count = stats['by_test_id'][test_id]
        info = CRYPTO_SPECIFIC_TESTS.get(test_id, {})
        name = info.get('name', 'Unknown')
        context_critical = "⚠️  CONTEXT CRITICAL" if info.get('context_critical') else ""
        print(f"  {test_id}: {count:4d} - {name} {context_critical}")
    
    print(f"\n🎚️  By Severity:")
    for severity in ['HIGH', 'MEDIUM', 'LOW']:
        if severity in stats['by_severity']:
            print(f"  {severity}: {stats['by_severity'][severity]}")
    
    print(f"\n🤔 Context Guess (automated, needs manual review!):")
    for context in ['LIKELY_SECURITY', 'LIKELY_NON_SECURITY', 'UNKNOWN']:
        if context in stats['by_context']:
            print(f"  {context}: {stats['by_context'][context]}")
    
    print("\n" + "="*70)
    print("⚠️  IMPORTANT: Context guesses are automated hints only!")
    print("   You MUST manually review each issue to determine:")
    print("   1. Is this in a security-critical context?")
    print("   2. Is this a real misuse or false positive?")
    print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='Filter Bandit results for crypto-specific issues only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python filter_bandit_crypto.py --bandit-dir ./bandit_results --output filtered.csv
  
  # Also save to database
  python filter_bandit_crypto.py --bandit-dir ./bandit_results --output filtered.csv --db crypto_usage.db
  
  # Just database (no CSV)
  python filter_bandit_crypto.py --bandit-dir ./bandit_results --db crypto_usage.db

Based on NDSS24 paper "Towards Precise Reporting of Cryptographic Misuses"
        """
    )
    
    parser.add_argument(
        '--bandit-dir',
        required=True,
        help='Directory containing Bandit JSON result files'
    )
    
    parser.add_argument(
        '--output',
        default=None,
        help='Output CSV file path (default: no CSV output)'
    )
    
    parser.add_argument(
        '--db',
        default=None,
        help='SQLite database to save results (default: no database)'
    )
    
    parser.add_argument(
        '--summary-only',
        action='store_true',
        help='Only print summary statistics, do not save results'
    )
    
    args = parser.parse_args()
    
    # Process results
    print("🔍 Processing Bandit results...")
    issues, stats = process_bandit_results(args.bandit_dir)
    
    # Print summary
    print_summary(stats)
    
    # Save results
    if not args.summary_only:
        if args.output:
            save_to_csv(issues, args.output)
        
        if args.db:
            save_to_database(issues, args.db)
        
        if not args.output and not args.db:
            print("⚠️  No output specified! Use --output or --db to save results.")
            print("   (Or use --summary-only to just see statistics)")
    
    print("\n✅ Done! Next steps:")
    print("   1. Review the CSV/database entries")
    print("   2. For each issue, check the code context")
    print("   3. Mark 'real_misuse' as YES or NO")
    print("   4. Add notes explaining your reasoning")
    print("\n   See NDSS24_PAPER_ANALYSIS.md for context-checking guidance!")


if __name__ == '__main__':
    main()

