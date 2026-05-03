#!/usr/bin/env python3
"""
Run Bandit (crypto misuse detector) on all downloaded repositories
This script automates running the existing Bandit tool on downloaded code

Usage:
    python run_bandit_detector.py --workdir ./repos --output-dir ./bandit_results
"""

import argparse
import json
import os
import subprocess
import sqlite3
from pathlib import Path
from datetime import datetime
from tqdm import tqdm

def log(msg: str):
    print(f"[{datetime.utcnow().isoformat()}] {msg}", flush=True)

def run_bandit_on_repo(repo_path, output_path):
    """
    Run Bandit on a single repository
    
    Args:
        repo_path: Path to the repository
        output_path: Path to save JSON output
    
    Returns:
        (success: bool, num_issues: int, error_msg: str)
    """
    try:
        # Run bandit with JSON output
        result = subprocess.run(
            ["bandit", "-r", str(repo_path), "-f", "json", "-o", str(output_path)],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout per repo
        )
        
        # Bandit returns exit code 1 if issues found, 0 if clean
        # We consider both success (just means it ran)
        if result.returncode in [0, 1]:
            # Read the JSON output to count issues
            try:
                with open(output_path, 'r') as f:
                    data = json.load(f)
                    num_issues = len(data.get('results', []))
                    return (True, num_issues, "")
            except:
                return (True, 0, "")
        else:
            return (False, 0, f"Bandit error: {result.stderr[:200]}")
            
    except subprocess.TimeoutExpired:
        return (False, 0, "Timeout after 5 minutes")
    except Exception as e:
        return (False, 0, f"Error: {str(e)[:200]}")

def get_project_info(db_path, repo_url):
    """Get project ID from database"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.execute("SELECT id FROM project WHERE repo_url = ?", (repo_url,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    except:
        return None

def store_bandit_results(db_path, project_id, num_issues, output_file):
    """Store Bandit results in database"""
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bandit_results (
                id INTEGER PRIMARY KEY,
                project_id INTEGER,
                num_issues INTEGER,
                output_file TEXT,
                scanned_at TEXT,
                FOREIGN KEY(project_id) REFERENCES project(id)
            )
        """)
        conn.execute("""
            INSERT INTO bandit_results (project_id, num_issues, output_file, scanned_at)
            VALUES (?, ?, ?, ?)
        """, (project_id, num_issues, output_file, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        log(f"Database error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Run Bandit crypto misuse detector on downloaded repositories"
    )
    parser.add_argument(
        "--workdir",
        default="./repos",
        help="Directory containing downloaded repos"
    )
    parser.add_argument(
        "--output-dir",
        default="./bandit_results",
        help="Directory to save Bandit results"
    )
    parser.add_argument(
        "--db",
        default="crypto_usage.db",
        help="Database to store results"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of repos to scan (for testing)"
    )
    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Skip first N repos (use with --limit for batching)"
    )
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Get list of downloaded repositories
    workdir = Path(args.workdir)
    if not workdir.exists():
        log(f"Error: workdir {workdir} does not exist")
        return
    
    repos = sorted([d for d in workdir.iterdir() if d.is_dir()])
    
    # Apply offset and limit
    if args.offset:
        repos = repos[args.offset:]
    if args.limit:
        repos = repos[:args.limit]
    
    total_repos = len([d for d in workdir.iterdir() if d.is_dir()])
    log(f"Found {len(repos)} repositories to scan (out of {total_repos} total)")
    if args.offset or args.limit:
        log(f"Scanning repos {args.offset} to {args.offset + len(repos) - 1}")
    
    # Statistics
    total_scanned = 0
    total_issues = 0
    failed_repos = []
    
    # Scan each repository
    for repo_dir in tqdm(repos, desc="Scanning repos"):
        repo_name = repo_dir.name
        output_file = output_dir / f"{repo_name}_bandit.json"
        
        log(f"Scanning {repo_name}...")
        
        success, num_issues, error_msg = run_bandit_on_repo(repo_dir, output_file)
        
        if success:
            total_scanned += 1
            total_issues += num_issues
            log(f"  ✓ {repo_name}: {num_issues} issues found")
            
            # Try to store in database
            # Reconstruct repo URL from directory name
            parts = repo_name.split('_', 1)
            if len(parts) == 2:
                repo_url = f"https://github.com/{parts[0]}/{parts[1]}"
                project_id = get_project_info(args.db, repo_url)
                if project_id:
                    store_bandit_results(args.db, project_id, num_issues, str(output_file))
        else:
            failed_repos.append((repo_name, error_msg))
            log(f"  ✗ {repo_name}: {error_msg}")
    
    # Print summary
    print("\n" + "="*60)
    print("BANDIT SCAN SUMMARY")
    print("="*60)
    print(f"Total repositories scanned: {total_scanned}")
    print(f"Total security issues found: {total_issues}")
    print(f"Average issues per repo: {total_issues/total_scanned if total_scanned > 0 else 0:.1f}")
    print(f"Failed scans: {len(failed_repos)}")
    
    if failed_repos:
        print("\nFailed repositories:")
        for name, error in failed_repos[:10]:  # Show first 10
            print(f"  - {name}: {error}")
    
    print(f"\nResults saved to: {output_dir}")
    print(f"Database updated: {args.db}")
    print("\nTo view detailed results:")
    print(f"  ls {output_dir}")
    print(f"  cat {output_dir}/<repo_name>_bandit.json")

if __name__ == "__main__":
    main()
