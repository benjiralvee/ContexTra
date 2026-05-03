#!/usr/bin/env python3
"""
Semgrep Detector Script
Runs Semgrep on Python repositories to detect crypto misuses.
"""

import argparse
import subprocess
import sqlite3
import json
from pathlib import Path
from datetime import datetime






def get_db_connection(db_path):
    """Connect to the SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def create_semgrep_tables(db_path):
    """Create tables for storing Semgrep scan results."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    # Create semgrep_scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS semgrep_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            scan_date TEXT,
            num_issues INTEGER,
            output_file TEXT,
            FOREIGN KEY (project_id) REFERENCES project(id)
        )
    """)
    
    conn.commit()
    conn.close()
    print("✅ Semgrep tables created/verified")


def get_project_id(conn, repo_name):
    """Get the project ID from the database (same logic as Bandit)."""
    cursor = conn.cursor()
    
    # Reconstruct repo URL from directory name (same as Bandit does)
    # repo_name is like: "owner_reponame"
    # repo_url is like: "https://github.com/owner/reponame"
    parts = repo_name.split('_', 1)  # Split on first underscore only
    if len(parts) == 2:
        repo_url = f"https://github.com/{parts[0]}/{parts[1]}"
        cursor.execute("SELECT id FROM project WHERE repo_url = ?", (repo_url,))
        result = cursor.fetchone()
        return result[0] if result else None
    return None


def store_semgrep_results(db_path, project_id, num_issues, output_file):
    """Store Semgrep scan results in the database."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO semgrep_scans (project_id, scan_date, num_issues, output_file)
        VALUES (?, ?, ?, ?)
    """, (project_id, datetime.now().isoformat(), num_issues, output_file))
    
    conn.commit()
    conn.close()


def run_semgrep_on_repo(repo_path, output_path):
    """Run Semgrep on a single repository."""
    try:
        # Run Semgrep with auto-config to catch EVERYTHING (filter afterwards)
        result = subprocess.run(
            [
                "semgrep",
                "--config=auto",  # Comprehensive: catches all security issues
                "--json",
                "--output", str(output_path),
                str(repo_path)
            ],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout per repo
        )
        
        return True
    except subprocess.TimeoutExpired:
        print(f"  ⏱️  Timeout scanning {repo_path.name}")
        return False
    except Exception as e:
        print(f"  ❌ Error scanning {repo_path.name}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Run Semgrep on Python repositories")
    parser.add_argument("--workdir", type=Path, default=Path("./repos"),
                        help="Directory containing cloned repos")
    parser.add_argument("--output-dir", type=Path, default=Path("./semgrep_results"),
                        help="Directory to store Semgrep JSON results")
    parser.add_argument("--db", type=Path, default=Path("crypto_usage.db"),
                        help="Path to SQLite database")
    parser.add_argument("--limit", type=int, default=None,
                        help="Maximum number of repos to scan")
    parser.add_argument("--offset", type=int, default=0,
                        help="Number of repos to skip")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip repos that already have Semgrep results")
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    args.output_dir.mkdir(parents=True, exist_ok=True)
    print(f"📁 Output directory: {args.output_dir}")
    
    # Create/verify database tables
    create_semgrep_tables(args.db)
    
    # Get list of repos
    repos = sorted([d for d in args.workdir.iterdir() if d.is_dir()])
    
    # Apply offset and limit
    if args.offset:
        repos = repos[args.offset:]
        print(f"⏭️  Skipping first {args.offset} repos")
    
    if args.limit:
        repos = repos[:args.limit]
        print(f"🎯 Limiting to {args.limit} repos")
    
    print(f"📊 Total repos to scan: {len(repos)}")
    
    # Connect to database
    conn = get_db_connection(args.db)
    
    # Track statistics
    scanned = 0
    skipped = 0
    errors = 0
    
    for i, repo_dir in enumerate(repos, 1):
        repo_name = repo_dir.name
        output_file = args.output_dir / f"{repo_name}_semgrep.json"
        
        # Skip if already scanned and --skip-existing is set
        if args.skip_existing and output_file.exists():
            print(f"[{i}/{len(repos)}] ⏭️  Skipping {repo_name} (already scanned)")
            skipped += 1
            continue
        
        print(f"[{i}/{len(repos)}] 🔍 Scanning {repo_name}...")
        
        # Get project ID
        project_id = get_project_id(conn, repo_name)
        if not project_id:
            print(f"  ⚠️  Project not found in database: {repo_name}")
            errors += 1
            continue
        
        # Run Semgrep
        success = run_semgrep_on_repo(repo_dir, output_file)
        
        if success:
            # Count issues in the output
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    num_issues = len(data.get('results', []))
                    print(f"  ✅ Found {num_issues} issues")
                    
                    # Store results in database
                    store_semgrep_results(args.db, project_id, num_issues, str(output_file))
                    scanned += 1
            except Exception as e:
                print(f"  ⚠️  Error processing results: {e}")
                errors += 1
        else:
            errors += 1
    
    conn.close()
    
    # Print summary
    print("\n" + "="*60)
    print("📊 SEMGREP SCAN SUMMARY")
    print("="*60)
    print(f"✅ Successfully scanned: {scanned}")
    print(f"⏭️  Skipped: {skipped}")
    print(f"❌ Errors: {errors}")
    print(f"📁 Results saved to: {args.output_dir}")
    print("="*60)


if __name__ == "__main__":
    main()

