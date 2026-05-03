#!/usr/bin/env python3
"""
Dlint Crypto Issue Filter
=========================

Filters Dlint scan results to extract only crypto-related security issues
and saves them to the database in a structured format.

Similar to filter_bandit_crypto.py and filter_semgrep_crypto.py

Date: November 2025
"""

import os
import sqlite3
import re
from datetime import datetime
from pathlib import Path
import argparse

# Configuration
DB_PATH = "crypto_usage.db"
DLINT_RESULTS_DIR = "dlint_results"

# Crypto-related Dlint codes (DUO codes)
CRYPTO_DLINT_CODES = {
    'DUO123': 'verify=False in requests (SSL/TLS)',
    'DUO130': 'insecure hashlib usage (weak hashing)',
    'DUO131': 'insecure random usage',
    'DUO132': 'hardcoded secret',
    'DUO133': 'weak cryptographic key',
    'DUO134': 'insecure cipher mode',
}

# Additional crypto-related keywords in messages
CRYPTO_KEYWORDS = [
    'crypto', 'hash', 'md5', 'sha1', 'sha256', 'ssl', 'tls',
    'certificate', 'random', 'encrypt', 'decrypt', 'cipher',
    'key', 'password', 'secret', 'token', 'des', 'aes', 'rsa',
    'verify', 'crypt'
]


def connect_db(db_path):
    """Connect to SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def create_filtered_table(conn, rebuild=False):
    """Create table for filtered crypto issues."""
    cursor = conn.cursor()
    
    if rebuild:
        print("🔄 Rebuilding dlint_crypto_filtered table...")
        cursor.execute("DROP TABLE IF EXISTS dlint_crypto_filtered")
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dlint_crypto_filtered (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_name TEXT NOT NULL,
            dlint_code TEXT,
            severity TEXT,
            filename TEXT,
            line_number INTEGER,
            column_number INTEGER,
            issue_text TEXT,
            code TEXT,
            manual_review TEXT DEFAULT 'TODO',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create indexes
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_dlint_crypto_repo 
        ON dlint_crypto_filtered(repo_name)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_dlint_crypto_code 
        ON dlint_crypto_filtered(dlint_code)
    """)
    
    conn.commit()
    print("✅ Table dlint_crypto_filtered ready")


def parse_dlint_line(line):
    """
    Parse a Dlint output line.
    
    Format: filename:line:col: CODE message
    OR:     filename|line|col|CODE|message (pipe-separated)
    
    Returns dict with parsed fields or None if invalid.
    """
    line = line.strip()
    if not line:
        return None
    
    # Try pipe-separated format first
    if '|' in line:
        parts = line.split('|')
        if len(parts) >= 4:
            return {
                'filename': parts[0],
                'line_number': int(parts[1]) if parts[1].isdigit() else 0,
                'column_number': int(parts[2]) if parts[2].isdigit() else 0,
                'dlint_code': parts[3],
                'issue_text': parts[4] if len(parts) > 4 else ''
            }
    
    # Try standard flake8 format: filepath:line:col: CODE message
    match = re.match(r'^(.+?):(\d+):(\d+):\s*(DUO\d+)\s*(.*)$', line)
    if match:
        return {
            'filename': match.group(1),
            'line_number': int(match.group(2)),
            'column_number': int(match.group(3)),
            'dlint_code': match.group(4),
            'issue_text': match.group(5)
        }
    
    return None


def is_crypto_related(dlint_code, issue_text):
    """Determine if a Dlint issue is crypto-related."""
    
    # Check if it's a known crypto code
    if dlint_code in CRYPTO_DLINT_CODES:
        return True
    
    # Check message for crypto keywords
    message_lower = issue_text.lower()
    for keyword in CRYPTO_KEYWORDS:
        if keyword in message_lower:
            return True
    
    return False


def extract_repo_name(filename):
    """Extract repository name from filename."""
    # Format: repos/owner_reponame/path/to/file.py
    # Want: owner_reponame
    
    if filename.startswith('repos/'):
        parts = filename.split('/')
        if len(parts) >= 2:
            return parts[1]
    
    return 'unknown'


def get_severity(dlint_code):
    """Map Dlint code to severity level."""
    # DUO codes starting with different ranges
    code_num = int(dlint_code[3:]) if dlint_code.startswith('DUO') else 0
    
    if code_num >= 100 and code_num < 110:
        return 'HIGH'  # Dangerous functions
    elif code_num >= 110 and code_num < 120:
        return 'MEDIUM'  # Security issues
    elif code_num >= 120 and code_num < 140:
        return 'HIGH'  # Crypto/SSL issues
    else:
        return 'MEDIUM'


def filter_and_save(results_dir, db_path, rebuild=False):
    """Filter Dlint results and save crypto issues to database."""
    
    conn = connect_db(db_path)
    create_filtered_table(conn, rebuild)
    cursor = conn.cursor()
    
    results_path = Path(results_dir)
    if not results_path.exists():
        print(f"❌ Results directory not found: {results_dir}")
        return
    
    # Get all .txt files
    txt_files = list(results_path.glob("*.txt"))
    print(f"📁 Found {len(txt_files)} result files")
    
    total_issues = 0
    crypto_issues = 0
    repos_processed = 0
    
    for txt_file in txt_files:
        repos_processed += 1
        
        with open(txt_file, 'r', errors='ignore') as f:
            for line in f:
                total_issues += 1
                
                # Parse line
                parsed = parse_dlint_line(line)
                if not parsed:
                    continue
                
                # Check if crypto-related
                if not is_crypto_related(parsed['dlint_code'], parsed['issue_text']):
                    continue
                
                crypto_issues += 1
                
                # Extract repo name
                repo_name = extract_repo_name(parsed['filename'])
                
                # Get severity
                severity = get_severity(parsed['dlint_code'])
                
                # Insert into database
                cursor.execute("""
                    INSERT INTO dlint_crypto_filtered
                    (repo_name, dlint_code, severity, filename, line_number, 
                     column_number, issue_text)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    repo_name,
                    parsed['dlint_code'],
                    severity,
                    parsed['filename'],
                    parsed['line_number'],
                    parsed['column_number'],
                    parsed['issue_text']
                ))
        
        if repos_processed % 100 == 0:
            print(f"  Processed {repos_processed}/{len(txt_files)} files...")
            conn.commit()
    
    conn.commit()
    
    # Print summary
    print(f"\n{'='*80}")
    print("📊 DLINT CRYPTO FILTERING SUMMARY")
    print(f"{'='*80}")
    print(f"Total Dlint issues:      {total_issues:,}")
    print(f"Crypto-related issues:   {crypto_issues:,}")
    print(f"Percentage:              {crypto_issues*100/total_issues:.1f}%" if total_issues > 0 else "N/A")
    print(f"Repos processed:         {repos_processed}")
    
    # Breakdown by code
    cursor.execute("""
        SELECT dlint_code, COUNT(*) as count
        FROM dlint_crypto_filtered
        GROUP BY dlint_code
        ORDER BY count DESC
    """)
    
    print(f"\n{'='*80}")
    print("🔐 CRYPTO ISSUES BY DLINT CODE")
    print(f"{'='*80}")
    for row in cursor.fetchall():
        code = row['dlint_code']
        count = row['count']
        description = CRYPTO_DLINT_CODES.get(code, 'Other crypto-related')
        print(f"{code:10} {count:>6} issues  - {description}")
    
    # Breakdown by severity
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM dlint_crypto_filtered
        GROUP BY severity
        ORDER BY count DESC
    """)
    
    print(f"\n{'='*80}")
    print("📊 CRYPTO ISSUES BY SEVERITY")
    print(f"{'='*80}")
    for row in cursor.fetchall():
        print(f"{row['severity']:10} {row['count']:>6} issues")
    
    # Top repos with most issues
    cursor.execute("""
        SELECT repo_name, COUNT(*) as count
        FROM dlint_crypto_filtered
        GROUP BY repo_name
        ORDER BY count DESC
        LIMIT 20
    """)
    
    print(f"\n{'='*80}")
    print("🔝 TOP 20 REPOS WITH MOST CRYPTO ISSUES")
    print(f"{'='*80}")
    for row in cursor.fetchall():
        print(f"{row['repo_name']:50} {row['count']:>6} issues")
    
    print(f"\n{'='*80}\n")
    
    conn.close()


def export_to_csv(db_path, output_file):
    """Export filtered results to CSV."""
    
    print(f"📤 Exporting to CSV: {output_file}")
    
    conn = connect_db(db_path)
    cursor = conn.cursor()
    
    # Get column names
    cursor.execute("SELECT * FROM dlint_crypto_filtered LIMIT 1")
    columns = [description[0] for description in cursor.description]
    
    # Export to CSV
    cursor.execute("""
        SELECT * FROM dlint_crypto_filtered
        ORDER BY repo_name, filename, line_number
    """)
    
    import csv
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        writer.writerows(cursor.fetchall())
    
    # Get count
    cursor.execute("SELECT COUNT(*) FROM dlint_crypto_filtered")
    count = cursor.fetchone()[0]
    
    print(f"✅ Exported {count:,} crypto issues to {output_file}")
    
    conn.close()


def main():
    """Main execution function."""
    
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║              🔍 Dlint Crypto Issue Filter                                ║
║                                                                           ║
║  Extracts crypto-related issues from Dlint scan results                 ║
║  Similar to Bandit and Semgrep filtering                                 ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """)
    
    parser = argparse.ArgumentParser(
        description="Filter Dlint results for crypto-related issues"
    )
    parser.add_argument(
        '--results-dir',
        type=str,
        default=DLINT_RESULTS_DIR,
        help=f'Directory with Dlint .txt results (default: {DLINT_RESULTS_DIR})'
    )
    parser.add_argument(
        '--db',
        type=str,
        default=DB_PATH,
        help=f'Database path (default: {DB_PATH})'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='filtered_dlint_915_repos.csv',
        help='Output CSV file (default: filtered_dlint_915_repos.csv)'
    )
    parser.add_argument(
        '--rebuild',
        action='store_true',
        help='Rebuild table (drop and recreate)'
    )
    
    args = parser.parse_args()
    
    # Filter and save to database
    filter_and_save(args.results_dir, args.db, args.rebuild)
    
    # Export to CSV
    export_to_csv(args.db, args.output)
    
    print("\n✅ Dlint crypto filtering complete!")
    print(f"📁 Results saved to: {args.db}")
    print(f"📁 CSV exported to: {args.output}")


if __name__ == "__main__":
    main()

