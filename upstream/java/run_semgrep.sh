#!/bin/bash

# Script to run Semgrep on all Java repositories
# Focuses on cryptography and security issues

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results/semgrep}"
mkdir -p "$RESULTS_DIR"

echo "======================================"
echo "Running Semgrep on 16 Java Repos"
echo "======================================"
echo ""

# Array of all repos
repos=(
    "spark"
    "hadoop"
    "ranger"
    "mongo-hadoop"
    "pig"
    "hive"
    "spring-framework"
    "struts"
    "kafka"
    "tomcat"
    "deeplearning4j"
    "jetty.project"
    "opencms-core"
    "ofbiz"
    "BroadleafCommerce"
    "openmrs-core"
    "BuildCms"
)

# Counter
counter=1
total=${#repos[@]}

# Run semgrep on each repo
for repo in "${repos[@]}"; do
    echo "[$counter/$total] Scanning $repo..."
    
    repo_path="repos/$repo"
    output_file="$RESULTS_DIR/${repo}_semgrep.json"
    
    if [ ! -d "$repo_path" ]; then
        echo "  ⚠️  Directory not found: $repo_path"
        ((counter++))
        continue
    fi
    
    # Run semgrep with crypto-focused rules
    # p/java           → general Java rules (includes crypto)
    # p/security-audit → security audit rules (includes crypto checks)
    semgrep scan \
        --config "p/java" \
        --config "p/security-audit" \
        --json \
        --output "$output_file" \
        --no-git-ignore \
        --max-memory 8000 \
        --timeout 300 \
        --timeout-threshold 0 \
        "$repo_path" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "  ✅ Complete"
    else
        echo "  ⚠️  Error scanning (may have timed out)"
    fi
    
    ((counter++))
    echo ""
done

echo ""
echo "======================================"
echo "Semgrep Scan Complete!"
echo "======================================"
echo ""
echo "Results saved in: $RESULTS_DIR/"
echo ""
echo "All results saved as JSON files."
echo "We'll analyze them with Python in the next step."

