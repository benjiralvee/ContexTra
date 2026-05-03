#!/usr/bin/env python3
"""
Dlint Detector Script
Runs Dlint (via flake8) on Python repositories to detect security issues.
"""

import argparse
import subprocess
import sqlite3
from pathlib import Path
from datetime import datetime


def get_db_connection(db_path):
    """Connect to the SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def create_dlint_tables(db_path):
    """Create tables for storing Dlint scan results."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    # Create dlint_scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dlint_scans (
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
    print("✅ Dlint tables created/verified")


def get_project_id(conn, repo_name):
    """Get the project ID from the database (same logic as Bandit/Semgrep)."""
    cursor = conn.cursor()
    
    # Reconstruct repo URL from directory name
    # repo_name is like: "owner_reponame"
    # repo_url is like: "https://github.com/owner/reponame"
    parts = repo_name.split('_', 1)  # Split on first underscore only
    if len(parts) == 2:
        repo_url = f"https://github.com/{parts[0]}/{parts[1]}"
        cursor.execute("SELECT id FROM project WHERE repo_url = ?", (repo_url,))
        result = cursor.fetchone()
        return result[0] if result else None
    return None


def store_dlint_results(db_path, project_id, num_issues, output_file):
    """Store Dlint scan results in the database."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO dlint_scans (project_id, scan_date, num_issues, output_file)
        VALUES (?, ?, ?, ?)
    """, (project_id, datetime.now().isoformat(), num_issues, output_file))
    
    conn.commit()
    conn.close()


def run_dlint_on_repo(repo_path, output_path):
    """Run Dlint (via flake8) on a single repository."""
    try:
        # Run flake8 with Dlint plugin (DUO codes only)
        result = subprocess.run(
            [
                "flake8",
                "--select=DUO",  # Only Dlint security checks
                "--format=%(path)s|%(row)d|%(col)d|%(code)s|%(text)s",  # Pipe-delimited
                str(repo_path)
            ],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout per repo
        )
        
        # Write output to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result.stdout)
        
        # Count issues
        num_issues = len([line for line in result.stdout.strip().split('\n') if line])
        
        return True, num_issues
        
    except subprocess.TimeoutExpired:
        print(f"  ⏱️  Timeout scanning {repo_path.name}")
        return False, 0
    except Exception as e:
        print(f"  ❌ Error scanning {repo_path.name}: {e}")
        return False, 0


def main():
    parser = argparse.ArgumentParser(description="Run Dlint on Python repositories")
    parser.add_argument("--workdir", type=Path, default=Path("./repos"),
                        help="Directory containing cloned repos")
    parser.add_argument("--output-dir", type=Path, default=Path("./dlint_results"),
                        help="Directory to store Dlint results")
    parser.add_argument("--db", type=Path, default=Path("crypto_usage.db"),
                        help="Path to SQLite database")
    parser.add_argument("--limit", type=int, default=None,
                        help="Maximum number of repos to scan")
    parser.add_argument("--offset", type=int, default=0,
                        help="Number of repos to skip")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip repos that already have Dlint results")
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    args.output_dir.mkdir(parents=True, exist_ok=True)
    print(f"📁 Output directory: {args.output_dir}")
    
    # Create/verify database tables
    create_dlint_tables(args.db)
    
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
    total_issues = 0
    
    for i, repo_dir in enumerate(repos, 1):
        repo_name = repo_dir.name
        output_file = args.output_dir / f"{repo_name}_dlint.txt"
        
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
        
        # Run Dlint
        success, num_issues = run_dlint_on_repo(repo_dir, output_file)
        
        if success:
            print(f"  ✅ Found {num_issues} issues")
            total_issues += num_issues
            
            # Store results in database
            store_dlint_results(args.db, project_id, num_issues, str(output_file))
            scanned += 1
        else:
            errors += 1
    
    conn.close()
    
    # Print summary
    print("\n" + "="*60)
    print("📊 DLINT SCAN SUMMARY")
    print("="*60)
    print(f"✅ Successfully scanned: {scanned}")
    print(f"📝 Total issues found: {total_issues}")
    print(f"⏭️  Skipped: {skipped}")
    print(f"❌ Errors: {errors}")
    print(f"📁 Results saved to: {args.output_dir}")
    print("="*60)


if __name__ == "__main__":
    main()



