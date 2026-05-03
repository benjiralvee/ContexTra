#!/bin/bash
#
# run_cryptoanalysis.sh
# 
# Runs CryptoAnalysis on all 16 Java repositories with proper error handling,
# multiple output formats, and metadata generation.
#
# Date: 2026-01-17
#

set +e  # Don't exit on errors - we want to continue with other repos

# ============================================================================
# CONFIGURATION — adjust these paths to your environment
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Tool paths (override with environment variables if needed)
MAVEN_HOME="${MAVEN_HOME:-$(command -v mvn && dirname "$(dirname "$(command -v mvn)")" || echo "")}"
ANT_HOME="${ANT_HOME:-$(command -v ant && dirname "$(dirname "$(command -v ant)")" || echo "")}"
JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null || echo "")}"

export PATH="${MAVEN_HOME:+$MAVEN_HOME/bin:}${ANT_HOME:+$ANT_HOME/bin:}$JAVA_HOME/bin:$PATH"
export JAVA_HOME

BASE_DIR="${BASE_DIR:-$SCRIPT_DIR}"
CRYPTOANALYSIS_JAR="$BASE_DIR/tools/CryptoAnalysis/apps/HeadlessJavaScanner-5.0.2-SNAPSHOT-jar-with-dependencies.jar"
RULES_DIR="$BASE_DIR/tools/CryptoAnalysis/Crypto-API-Rules/JavaCryptographicArchitecture/src"
REPOS_DIR="${REPOS_DIR:-$BASE_DIR/repos}"
RESULTS_BASE="$BASE_DIR/results/cryptoanalysis"

# Java memory and stack settings
JAVA_HEAP="16g"
JAVA_STACK="512m"

# CryptoAnalysis settings
TIMEOUT_MS="600000"  # 10 minutes per seed
REPORT_FORMATS="CMD,TXT,SARIF,CSV,CSV_SUMMARY"

# Tool version for metadata
CRYPTOANALYSIS_VERSION="5.0.2-SNAPSHOT"
RULES_VERSION="JavaCryptographicArchitecture"

# Logging
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Build a repository if JAR is missing
build_repo() {
  local repo=$1
  local repo_path="$REPOS_DIR/$repo"
  
  log "Building $repo..."
  
  cd "$repo_path" || return 1
  
  # Determine build system and build
  if [ -f "pom.xml" ]; then
    log "  Using Maven..."
    mvn clean package -DskipTests -q > /dev/null 2>&1
    local exit_code=$?
  elif [ -f "build.gradle" ] || [ -f "build.gradle.kts" ]; then
    log "  Using Gradle..."
    if [ -f "gradlew" ]; then
      ./gradlew build -x test -q > /dev/null 2>&1
    else
      gradle build -x test -q > /dev/null 2>&1
    fi
    local exit_code=$?
  elif [ -f "build.xml" ]; then
    log "  Using Ant..."
    ant jar -q > /dev/null 2>&1
    local exit_code=$?
  else
    log "  ⚠️  Unknown build system"
    return 1
  fi
  
  cd - > /dev/null
  
  if [ $exit_code -eq 0 ]; then
    log "  ✅ Build successful"
    return 0
  else
    log "  ❌ Build failed (exit code: $exit_code)"
    return 1
  fi
}

# Find the main JAR for a repository
find_repo_jar() {
  local repo=$1
  local repo_path="$REPOS_DIR/$repo"
  local jar_path=""
  
  case "$repo" in
    spark)
      jar_path=$(find "$repo_path" -name "spark-core_*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    hadoop)
      jar_path=$(find "$repo_path" -name "hadoop-common-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    ranger)
      jar_path=$(find "$repo_path" -name "ranger-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc\|example" | head -1)
      ;;
    mongo-hadoop)
      jar_path=$(find "$repo_path" -name "mongo-hadoop-core-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    pig)
      jar_path=$(find "$repo_path" -name "pig-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc\|withouthadoop" | head -1)
      ;;
    hive)
      jar_path=$(find "$repo_path" -name "hive-exec-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    spring-framework)
      jar_path=$(find "$repo_path" -name "spring-core-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    struts)
      jar_path=$(find "$repo_path" -name "struts2-core-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    kafka)
      jar_path=$(find "$repo_path" -name "kafka_*.jar" -path "*/build/libs/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    tomcat)
      jar_path=$(find "$repo_path" -name "catalina.jar" -o -name "tomcat-coyote.jar" | head -1)
      ;;
    deeplearning4j)
      jar_path=$(find "$repo_path" -name "deeplearning4j-core-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    jetty.project)
      jar_path=$(find "$repo_path" -name "jetty-server-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    opencms-core)
      jar_path=$(find "$repo_path" -name "opencms-core-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    ofbiz)
      jar_path=$(find "$repo_path" -name "ofbiz.jar" -o -name "ofbiz-base.jar" | head -1)
      ;;
    BroadleafCommerce)
      jar_path=$(find "$repo_path" -name "broadleaf-framework-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
    openmrs-core)
      jar_path=$(find "$repo_path" -name "openmrs-api-*.jar" -path "*/target/*" | grep -v "tests\|sources\|javadoc" | head -1)
      ;;
  esac
  
  echo "$jar_path"
}

# Run CryptoAnalysis on a single repository
run_cryptoanalysis() {
  local repo=$1
  local jar_path=$2
  local output_dir="$RESULTS_BASE/$repo"
  local log_file="$output_dir/${repo}_cryptoanalysis.log"
  local metadata_file="$output_dir/${repo}_cryptoanalysis.metadata.json"
  
  log "Starting CryptoAnalysis for $repo..."
  log "  JAR: $jar_path"
  log "  Output: $output_dir"
  
  # Create output directory
  mkdir -p "$output_dir"
  
  # Record start time
  local start_time=$(date +%s)
  local start_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  
  # Run CryptoAnalysis (redirect stdout and stderr to log file)
  java -Xmx${JAVA_HEAP} -Xss${JAVA_STACK} \
    -jar "$CRYPTOANALYSIS_JAR" \
    --appPath "$jar_path" \
    --rulesDir "$RULES_DIR" \
    --reportPath "$output_dir" \
    --reportFormat "$REPORT_FORMATS" \
    --timeout "$TIMEOUT_MS" \
    --cg SPARK \
    > "$log_file" 2>&1
  
  local exit_code=$?
  
  # Record end time
  local end_time=$(date +%s)
  local end_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local duration=$((end_time - start_time))
  
  # Determine status
  local status="unknown"
  local status_message=""
  
  if [ $exit_code -eq 0 ]; then
    status="success"
    status_message="Analysis completed successfully"
  elif grep -q "StackOverflowError" "$log_file" 2>/dev/null; then
    status="stack_overflow"
    status_message="Analysis failed: StackOverflowError (project too complex)"
  elif grep -q "OutOfMemoryError" "$log_file" 2>/dev/null; then
    status="out_of_memory"
    status_message="Analysis failed: OutOfMemoryError"
  elif grep -q "Exception" "$log_file" 2>/dev/null; then
    status="exception"
    status_message="Analysis failed with exception (see log)"
  else
    status="error"
    status_message="Analysis failed with exit code $exit_code"
  fi
  
  # Extract violation counts from log (if available)
  local total_violations=0
  local typestate_errors=0
  local constraint_errors=0
  local required_predicate_errors=0
  local incomplete_operation_errors=0
  local imprecise_value_extraction_errors=0
  local objects_analyzed=0
  
  if [ -f "$log_file" ]; then
    objects_analyzed=$(grep "Number of Objects analyzed:" "$log_file" 2>/dev/null | sed 's/.*: //' | tr -d ' ')
    typestate_errors=$(grep "TypestateError:" "$log_file" 2>/dev/null | sed 's/.*: //' | tr -d ' ')
    constraint_errors=$(grep "ConstraintError:" "$log_file" 2>/dev/null | sed 's/.*: //' | tr -d ' ')
    required_predicate_errors=$(grep "RequiredPredicateError:" "$log_file" 2>/dev/null | sed 's/.*: //' | tr -d ' ')
    incomplete_operation_errors=$(grep "IncompleteOperationError:" "$log_file" 2>/dev/null | sed 's/.*: //' | tr -d ' ')
    imprecise_value_extraction_errors=$(grep "ImpreciseValueExtractionError:" "$log_file" 2>/dev/null | sed 's/.*: //' | tr -d ' ')
    
    # Ensure we have numbers (default to 0 if empty)
    objects_analyzed=${objects_analyzed:-0}
    typestate_errors=${typestate_errors:-0}
    constraint_errors=${constraint_errors:-0}
    required_predicate_errors=${required_predicate_errors:-0}
    incomplete_operation_errors=${incomplete_operation_errors:-0}
    imprecise_value_extraction_errors=${imprecise_value_extraction_errors:-0}
    
    # Calculate total violations
    total_violations=$((typestate_errors + constraint_errors + required_predicate_errors + incomplete_operation_errors + imprecise_value_extraction_errors))
  fi
  
  # Generate metadata JSON
  cat > "$metadata_file" << EOF
{
  "repo_name": "$repo",
  "tool": "CryptoAnalysis",
  "tool_version": "$CRYPTOANALYSIS_VERSION",
  "rules_version": "$RULES_VERSION",
  "jar_analyzed": "$jar_path",
  "start_time": "$start_timestamp",
  "end_time": "$end_timestamp",
  "duration_seconds": $duration,
  "exit_code": $exit_code,
  "status": "$status",
  "status_message": "$status_message",
  "settings": {
    "java_heap": "$JAVA_HEAP",
    "java_stack": "$JAVA_STACK",
    "timeout_ms": $TIMEOUT_MS,
    "report_formats": "$REPORT_FORMATS"
  },
  "summary": {
    "objects_analyzed": $objects_analyzed,
    "total_violations": $total_violations,
    "typestate_errors": $typestate_errors,
    "constraint_errors": $constraint_errors,
    "required_predicate_errors": $required_predicate_errors,
    "incomplete_operation_errors": $incomplete_operation_errors,
    "imprecise_value_extraction_errors": $imprecise_value_extraction_errors
  },
  "output_files": {
    "log": "${repo}_cryptoanalysis.log",
    "txt_report": "CryptoAnalysis-Report.txt",
    "sarif_report": "CryptoAnalysis-Report.sarif",
    "csv_report": "CryptoAnalysis-Report.csv",
    "csv_summary": "CryptoAnalysis-Report-Summary.csv"
  }
}
EOF
  
  # Log results
  if [ "$status" = "success" ]; then
    log "✅ $repo: SUCCESS (${duration}s, $total_violations violations, $objects_analyzed objects)"
  else
    log "❌ $repo: $status ($status_message)"
  fi
  
  return $exit_code
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

log "========================================="
log "CryptoAnalysis Analysis"
log "========================================="
log ""
log "Configuration:"
log "  Java: $(java -version 2>&1 | head -1)"
log "  Heap: $JAVA_HEAP"
log "  Stack: $JAVA_STACK"
log "  Timeout: ${TIMEOUT_MS}ms"
log "  Rules: $RULES_VERSION"
log "  Output formats: $REPORT_FORMATS"
log ""

# Create base results directory
mkdir -p "$RESULTS_BASE"

# Array of all repositories
REPOS=(
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
)

# Counters
total_repos=${#REPOS[@]}
success_count=0
failure_count=0
skipped_count=0

# Process each repository
for i in "${!REPOS[@]}"; do
  repo="${REPOS[$i]}"
  counter=$((i + 1))
  
  log ""
  log "========================================="
  log "Repository $counter/$total_repos: $repo"
  log "========================================="
  
  # Check if repo exists
  if [ ! -d "$REPOS_DIR/$repo" ]; then
    log "⚠️  Repository directory not found: $REPOS_DIR/$repo"
    log "    Skipping..."
    ((skipped_count++))
    continue
  fi
  
  # Find JAR
  log "Searching for JAR..."
  jar_path=$(find_repo_jar "$repo")
  
  if [ -z "$jar_path" ] || [ ! -f "$jar_path" ]; then
    log "⚠️  No suitable JAR found for $repo"
    log "    Attempting to build..."
    
    # Try to build the repo
    if build_repo "$repo"; then
      # Try finding JAR again
      jar_path=$(find_repo_jar "$repo")
      
      if [ -z "$jar_path" ] || [ ! -f "$jar_path" ]; then
        log "❌ Build succeeded but still no JAR found"
        log "    Skipping..."
        ((skipped_count++))
        continue
      else
        log "✅ JAR found after build: $jar_path"
      fi
    else
      log "❌ Build failed"
      log "    Skipping..."
      ((skipped_count++))
      continue
    fi
  fi
  
  # Run analysis
  if run_cryptoanalysis "$repo" "$jar_path"; then
    ((success_count++))
  else
    ((failure_count++))
  fi
done

# ============================================================================
# FINAL SUMMARY
# ============================================================================

log ""
log "========================================="
log "FINAL SUMMARY"
log "========================================="
log "Total repositories: $total_repos"
log "✅ Successful: $success_count"
log "❌ Failed: $failure_count"
log "⚠️  Skipped: $skipped_count"
log ""
log "Results saved to: $RESULTS_BASE"
log ""
log "========================================="
log "DONE"
log "========================================="

exit 0

