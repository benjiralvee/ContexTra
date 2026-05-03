#!/bin/bash
#
# run_codeql.sh
# 
# Runs CodeQL analysis on all 16 Java repositories with crypto-focused queries
#
# Date: 2026-01-20
#

set -e

# ============================================================================
# CONFIGURATION — adjust these paths to your environment
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BASE_DIR="${BASE_DIR:-$SCRIPT_DIR}"
REPOS_DIR="${REPOS_DIR:-$BASE_DIR/repos}"
RESULTS_DIR="${RESULTS_DIR:-$BASE_DIR/results/codeql}"
CODEQL_QUERIES="${CODEQL_QUERIES:-$BASE_DIR/tools/codeql-repo}"
DATABASES_DIR="${DATABASES_DIR:-$BASE_DIR/codeql-databases}"

# Java environment — set JAVA*_HOME for each JDK version you have installed.
# On macOS: /Library/Java/JavaVirtualMachines/<jdk>/Contents/Home
# On Linux: /usr/lib/jvm/<jdk>
JAVA8_HOME="${JAVA8_HOME:-$(/usr/libexec/java_home -v 1.8 2>/dev/null || echo "")}"
JAVA11_HOME="${JAVA11_HOME:-$(/usr/libexec/java_home -v 11 2>/dev/null || echo "")}"
JAVA17_HOME="${JAVA17_HOME:-$(/usr/libexec/java_home -v 17 2>/dev/null || echo "")}"
JAVA21_HOME="${JAVA21_HOME:-$(/usr/libexec/java_home -v 21 2>/dev/null || echo "")}"
JAVA24_HOME="${JAVA24_HOME:-$(/usr/libexec/java_home -v 24 2>/dev/null || echo "")}"

# CodeQL binary
CODEQL_BIN="${CODEQL_BIN:-$(command -v codeql 2>/dev/null || echo "codeql")}"
MAVEN_HOME="${MAVEN_HOME:-$(command -v mvn >/dev/null 2>&1 && dirname "$(dirname "$(command -v mvn)")" || echo "")}"
ANT_HOME="${ANT_HOME:-$(command -v ant >/dev/null 2>&1 && dirname "$(dirname "$(command -v ant)")" || echo "")}"

# Maven options for large builds
export MAVEN_OPTS="-Xmx4g -XX:MaxMetaspaceSize=1g"

# Maven settings for OpenMRS (HTTP → HTTPS mirror)
MAVEN_SETTINGS_OPENMRS="${MAVEN_SETTINGS_OPENMRS:-$BASE_DIR/tools/maven-settings-openmrs.xml}"

# Function to set Java version for a specific repo (Bash 3.2 compatible - no associative arrays)
set_java_for_repo() {
  local repo=$1
  local jhome=""
  
  # Select Java version based on repo requirements
  case "$repo" in
    # Java 8 repos (older projects, strict requirements, old Gradle)
    hadoop|hive|pig|ranger|mongo-hadoop|BroadleafCommerce|openmrs-core|ofbiz|jetty.project)
      jhome="$JAVA8_HOME"
      ;;
    
    # Java 11 repos (modern, but pre-17)
    deeplearning4j|opencms-core)
      jhome="$JAVA11_HOME"
      ;;
    
    # Java 17 repos (latest LTS, modern projects)
    spark|kafka|struts)
      jhome="$JAVA17_HOME"
      ;;
    
    # Java 21 repos (very recent, requires Java 21+)
    tomcat)
      jhome="$JAVA21_HOME"
      ;;
    
    # Java 24 repos (spring-framework needs JDK 25 toolchain, use 24 as closest)
    spring-framework)
      jhome="$JAVA24_HOME"
      ;;
    
    # Special case: jetty.project (has a dot, needs Java 8 for old source level)
    jetty.project)
      jhome="$JAVA8_HOME"
      ;;
    
    # Default fallback
    *)
      jhome="$JAVA11_HOME"
      ;;
  esac
  
  if [ -z "$jhome" ] || [ ! -d "$jhome" ]; then
    log "❌ No suitable JDK found for $repo"
    return 2
  fi
  
  export JAVA_HOME="$jhome"
  # Prepend Java/build tools to PATH (keep existing PATH for codeql, etc.)
  export PATH="$JAVA_HOME/bin:$MAVEN_HOME/bin:$ANT_HOME/bin:/usr/local/codeql:$PATH"
  
  # Gradle toolchain configuration (as system properties - more reliable than env vars)
  local jvm_dir="/Library/Java/JavaVirtualMachines"
  [ -d "/usr/lib/jvm" ] && jvm_dir="/usr/lib/jvm"
  export GRADLE_JAVA_TOOLCHAIN_OPTS="-Dorg.gradle.java.installations.auto-download=false -Dorg.gradle.java.installations.auto-detect=true -Dorg.gradle.java.installations.paths=$jvm_dir -Dorg.gradle.java.home=$JAVA_HOME"
  
  # Safety check: ensure codeql is still accessible
  if ! command -v "$CODEQL_BIN" >/dev/null 2>&1; then
    log "  ❌ ERROR: CodeQL binary not found at $CODEQL_BIN after setting JAVA_HOME"
    return 2
  fi
  
  log "  Using Java: $(basename $(dirname $(dirname $JAVA_HOME)))"
}

# Repositories to analyze (ONLY the 8 that failed in test batch - already have spark, ranger, pig, kafka working)
REPOS=(
  "mongo-hadoop"
  "spring-framework"
  "struts"
  "tomcat"
  "jetty.project"
  "opencms-core"
  "ofbiz"
  "openmrs-core"
)

# Logging
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# ============================================================================
# PREFLIGHT CHECKS
# ============================================================================

log "Starting CodeQL analysis..."
log ""

# Check if CodeQL is installed
if ! command -v codeql &> /dev/null; then
  log "❌ ERROR: CodeQL is not installed or not in PATH"
  log "Please install CodeQL first (see CODEQL_INSTALLATION_GUIDE.txt)"
  exit 1
fi

log "✅ CodeQL version: $(codeql version | head -1)"
log "   Using pack-based queries (codeql/java-queries)"

# Create directories
mkdir -p "$DATABASES_DIR"
mkdir -p "$RESULTS_DIR"
mkdir -p "$(dirname "$MAVEN_SETTINGS_OPENMRS")"

# Create Maven settings file for OpenMRS (mirrors HTTP repo to HTTPS)
log "📝 Creating Maven settings for OpenMRS (HTTP → HTTPS mirror)..."
cat > "$MAVEN_SETTINGS_OPENMRS" <<'EOF'
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <mirrors>
    <mirror>
      <id>openmrs-repo-https</id>
      <mirrorOf>openmrs-repo</mirrorOf>
      <url>https://mavenrepo.openmrs.org/nexus/content/repositories/public</url>
    </mirror>
  </mirrors>
</settings>
EOF

log ""

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Detect build command for a repository
detect_build_command() {
  local repo=$1
  local repo_path="$REPOS_DIR/$repo"
  
  cd "$repo_path"
  
  # Ensure gradlew is executable
  [ -f gradlew ] && chmod +x gradlew
  
  # ===== REPO-SPECIFIC BUILD COMMANDS (no clean!) =====
  
  # Hadoop: only hadoop-common (safest, avoids protoc/native issues)
  if [ "$repo" = "hadoop" ]; then
    echo "mvn -B -DskipTests -DskipITs -Dmaven.javadoc.skip=true -Dskip.nativetests -Drequire.snappy=false -Drequire.zstd=false -Drequire.openssl=false -Drat.skip=true -Denforcer.skip=true -pl hadoop-common-project/hadoop-common -am package"
    return
  fi
  
  # Spark: MUST use clean+package to force compilation for CodeQL
  if [ "$repo" = "spark" ] && [ -x "./build/mvn" ]; then
    echo "./build/mvn -DskipTests -DskipITs -Dmaven.javadoc.skip=true clean package"
    return
  fi
  
  # Kafka: force recompilation for CodeQL tracer
  if [ "$repo" = "kafka" ]; then
    echo "./gradlew --no-daemon clean -x test -x check classes --rerun-tasks --no-build-cache --stacktrace --info"
    return
  fi
  
  # Spring Framework: Force Gradle to use JAVA_HOME (will fail if needs JDK 25)
  if [ "$repo" = "spring-framework" ]; then
    echo "./gradlew --no-daemon -Dorg.gradle.java.home=$JAVA_HOME -x test -x check classes --stacktrace --info"
    return
  fi
  
  # mongo-hadoop: old Gradle wrapper (minimal flags for old Gradle compatibility)
  if [ "$repo" = "mongo-hadoop" ]; then
    echo "./gradlew --no-daemon -Dorg.gradle.java.home=$JAVA_HOME -x test -x check classes --stacktrace"
    return
  fi
  
  # Jetty: Build only server module, force recompilation (clean+compile ensures CodeQL sees compilation)
  if [ "$repo" = "jetty.project" ]; then
    echo "mvn -B -U -DskipTests -Dmaven.javadoc.skip=true -Dspotbugs.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -Drat.skip=true -pl jetty-server -am clean compile"
    return
  fi
  
  # Tomcat: just compile (download often fails)
  if [ "$repo" = "tomcat" ]; then
    echo "ant -noinput compile"
    return
  fi
  
  # Struts: FORCE recompilation so CodeQL traces javac (add clean)
  if [ "$repo" = "struts" ]; then
    echo "mvn -B -DskipTests -Dmaven.javadoc.skip=true -Dspotbugs.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -Drat.skip=true -Dgpg.skip=true -Dlicense.skip=true -pl core -am clean compile"
    return
  fi
  
  # Deeplearning4j: huge reactor, needs install
  if [ "$repo" = "deeplearning4j" ]; then
    echo "mvn -B -DskipTests -Dmaven.javadoc.skip=true -Dspotbugs.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -Drat.skip=true install"
    return
  fi
  
  # BroadleafCommerce: install
  if [ "$repo" = "BroadleafCommerce" ]; then
    echo "mvn -B -DskipTests -Dmaven.javadoc.skip=true -Dspotbugs.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -Drat.skip=true install"
    return
  fi
  
  # OpenMRS: Use custom settings to mirror HTTP repo to HTTPS
  if [ "$repo" = "openmrs-core" ]; then
    echo "mvn -s $MAVEN_SETTINGS_OPENMRS -B -DskipTests -Dmaven.javadoc.skip=true -Dspotbugs.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -Drat.skip=true install"
    return
  fi
  
  # Hive: complex, needs install
  if [ "$repo" = "hive" ]; then
    echo "mvn -B -DskipTests -Dmaven.javadoc.skip=true -Dspotbugs.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -Drat.skip=true install"
    return
  fi
  
  # Ranger: use compile (not install), skip enunciate plugin
  if [ "$repo" = "ranger" ]; then
    echo "mvn -B -DskipTests -DskipITs -Dmaven.javadoc.skip=true -Denunciate.skip=true -Dspotbugs.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true clean compile"
    return
  fi
  
  # Pig: ant compile with -noinput
  if [ "$repo" = "pig" ]; then
    echo "ant -noinput compile"
    return
  fi
  
  # ofbiz: build.xml has no "compile" target. Auto-detect or use Gradle wrapper.
  if [ "$repo" = "ofbiz" ]; then
    # Prefer Gradle wrapper if present (common in many OFBiz checkouts)
    if [ -f "gradlew" ]; then
      chmod +x ./gradlew 2>/dev/null || true
      echo "./gradlew --no-daemon -Dorg.gradle.java.home=$JAVA_HOME -x test build --stacktrace"
      return
    fi

    # Ant fallback: choose build/jar/all/default target (in that order)
    if [ -f "build.xml" ]; then
      local ant_default
      ant_default=$(ant -p 2>/dev/null | awk -F': ' '/Default target:/ {print $2; exit}')

      if ant -p 2>/dev/null | awk '{print $1}' | grep -qx "build"; then
        echo "ant -noinput build"
      elif ant -p 2>/dev/null | awk '{print $1}' | grep -qx "jar"; then
        echo "ant -noinput jar"
      elif ant -p 2>/dev/null | awk '{print $1}' | grep -qx "all"; then
        echo "ant -noinput all"
      elif [ -n "$ant_default" ]; then
        echo "ant -noinput $ant_default"
      else
        echo ""  # can't determine target
      fi
      return
    fi
  fi
  
  # opencms-core: No gradlew exists, requires system Gradle 6.9.4 (incompatible with 9.3)
  if [ "$repo" = "opencms-core" ]; then
    # Check if Gradle 6.9.4 is available (user would need to install it manually)
    if [ -d "$HOME/.sdkman/candidates/gradle/6.9.4" ]; then
      echo "$HOME/.sdkman/candidates/gradle/6.9.4/bin/gradle --no-daemon -Dorg.gradle.java.home=$JAVA_HOME -x test classes --stacktrace"
    else
      log "  ⚠️  opencms-core requires Gradle 6.9.4 (not found in ~/.sdkman/candidates/gradle/6.9.4)"
      log "  Skipping build. To fix: sdk install gradle 6.9.4"
      echo ""  # Empty command skips the build
    fi
    return
  fi
  
  # ===== DEFAULT BUILD COMMANDS (NO clean!) =====
  
  if [ -f "pom.xml" ]; then
    # Maven: compile (no clean!)
    echo "mvn -B -DskipTests -DskipITs -Dmaven.javadoc.skip=true -Dspotbugs.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -Drat.skip=true compile"
  elif [ -f "build.gradle" ] || [ -f "build.gradle.kts" ]; then
    # Gradle: compileJava (no clean!)
    if [ -f "gradlew" ]; then
      echo "./gradlew --no-daemon compileJava -x test -x check"
    else
      echo "gradle --no-daemon compileJava -x test -x check"
    fi
  elif [ -f "build.xml" ]; then
    echo "ant compile"
  else
    echo ""  # No build command
  fi
}

# Create CodeQL database for a repository
create_database() {
  local repo=$1
  local db_path="$DATABASES_DIR/${repo}-db"
  local repo_path="$REPOS_DIR/$repo"
  
  # Skip if database already exists
  if [ -d "$db_path" ]; then
    log "  ℹ️  Database already exists, skipping creation"
    return 0
  fi
  
  log "  Creating CodeQL database..."
  
  # Ensure gradlew is executable (critical for Gradle projects)
  [ -f "$repo_path/gradlew" ] && chmod +x "$repo_path/gradlew"
  
  # Detect build command
  local build_cmd=$(detect_build_command "$repo")
  
  if [ -z "$build_cmd" ]; then
    log "  ⚠️  No build system detected, attempting without build command..."
    "$CODEQL_BIN" database create "$db_path" \
      --language=java \
      --source-root="$repo_path" \
      > "$RESULTS_DIR/${repo}_db_creation.log" 2>&1
  else
    log "  Build command: $build_cmd"
    "$CODEQL_BIN" database create "$db_path" \
      --language=java \
      --source-root="$repo_path" \
      --command="$build_cmd" \
      > "$RESULTS_DIR/${repo}_db_creation.log" 2>&1
  fi
  
  local exit_code=$?
  
  if [ $exit_code -eq 0 ]; then
    log "  ✅ Database created successfully"
    return 0
  else
    log "  ❌ Database creation failed (exit code: $exit_code)"
    log "     See log: $RESULTS_DIR/${repo}_db_creation.log"
    log "     ---- last 60 lines of log ----"
    tail -n 160 "$RESULTS_DIR/${repo}_db_creation.log" 2>/dev/null | sed 's/^/     /' || log "     (log file not found)"
    log "     -----------------------------"
    return 1
  fi
}

# Run CodeQL queries on a database
run_queries() {
  local repo=$1
  local db_path="$DATABASES_DIR/${repo}-db"
  local output_dir="$RESULTS_DIR/$repo"
  
  mkdir -p "$output_dir"
  
  log "  Running CodeQL crypto-specific queries (pack-based)..."
  
  # Finalize database if not already finalized (critical for broken DBs)
  "$CODEQL_BIN" database finalize "$db_path" >/dev/null 2>&1 || true
  
  # Use pack-based queries (matches CLI version, no repo clone needed)
  # CWE-327: Broken/Risky Crypto
  # CWE-330: Insecure Randomness  
  # CWE-780: RSA without OAEP
  # CWE-798: Hardcoded Credentials
  set +e
  "$CODEQL_BIN" database analyze "$db_path" \
    --format=sarif-latest \
    --output="$output_dir/${repo}_crypto.sarif" \
    --sarif-category=crypto \
    --download \
    "codeql/java-queries:Security/CWE/CWE-327/BrokenCryptoAlgorithm.ql" \
    "codeql/java-queries:Security/CWE/CWE-327/MaybeBrokenCryptoAlgorithm.ql" \
    "codeql/java-queries:Security/CWE/CWE-330/InsecureRandomness.ql" \
    "codeql/java-queries:Security/CWE/CWE-780/RsaWithoutOaep.ql" \
    "codeql/java-queries:Security/CWE/CWE-798/HardcodedCredentialsApiCall.ql" \
    "codeql/java-queries:Security/CWE/CWE-798/HardcodedCredentialsComparison.ql" \
    "codeql/java-queries:Security/CWE/CWE-798/HardcodedPasswordField.ql" \
    > "$output_dir/${repo}_analysis.log" 2>&1
  
  local exit_code=$?
  set -e
  
  if [ $exit_code -eq 0 ]; then
    log "  ✅ Crypto queries completed successfully"
  else
    log "  ❌ Crypto queries failed (exit code: $exit_code)"
    log "     ---- last 80 lines of analysis log ----"
    tail -n 80 "$output_dir/${repo}_analysis.log" 2>/dev/null | sed 's/^/     /'
    log "     ----------------------------------------"
    return $exit_code
  fi
  
  # Convert SARIF to CSV for easier analysis
  log "  Converting results to CSV..."
  python3 - <<EOF > "$output_dir/${repo}_results.csv" 2>/dev/null || true
import json
import csv
import sys

sarif_files = [
    "$output_dir/${repo}_crypto.sarif"
]

results = []

for sarif_file in sarif_files:
    try:
        with open(sarif_file, 'r') as f:
            data = json.load(f)
            for run in data.get('runs', []):
                for result in run.get('results', []):
                    rule_id = result.get('ruleId', 'Unknown')
                    message = result.get('message', {}).get('text', '')
                    locations = result.get('locations', [])
                    
                    for loc in locations:
                        physical_loc = loc.get('physicalLocation', {})
                        artifact_loc = physical_loc.get('artifactLocation', {})
                        region = physical_loc.get('region', {})
                        
                        results.append({
                            'rule_id': rule_id,
                            'message': message,
                            'file': artifact_loc.get('uri', ''),
                            'start_line': region.get('startLine', ''),
                            'level': result.get('level', 'warning')
                        })
    except:
        pass

# Write CSV
if results:
    with open("$output_dir/${repo}_results.csv", 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['rule_id', 'level', 'file', 'start_line', 'message'])
        writer.writeheader()
        writer.writerows(results)
    print(f"Exported {len(results)} findings to CSV")
else:
    print("No findings")
EOF
  
  return 0
}

# Generate metadata for a repository
generate_metadata() {
  local repo=$1
  local output_dir="$RESULTS_DIR/$repo"
  local db_path="$DATABASES_DIR/${repo}-db"
  
  # Count findings from CSV
  local findings=0
  if [ -f "$output_dir/${repo}_results.csv" ]; then
    findings=$(tail -n +2 "$output_dir/${repo}_results.csv" | wc -l | xargs)
  fi
  
  # Check database status
  local db_status="not_created"
  if [ -d "$db_path" ]; then
    db_status="created"
  fi
  
  # Generate metadata JSON
  cat > "$output_dir/${repo}_codeql.metadata.json" <<EOF
{
  "repository": "$repo",
  "tool": "CodeQL",
  "analysis_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "database_status": "$db_status",
  "database_path": "$db_path",
  "findings_count": $findings,
  "outputs": {
    "security_sarif": "${repo}_security.sarif",
    "crypto_sarif": "${repo}_crypto.sarif",
    "csv": "${repo}_results.csv",
    "log": "${repo}_analysis.log"
  }
}
EOF
}

# ============================================================================
# MAIN ANALYSIS LOOP
# ============================================================================

log "==========================================="
log "Starting CodeQL Analysis"
log "==========================================="
log "Total repositories: ${#REPOS[@]}"
log ""

success_count=0
failed_count=0
skipped_count=0

for i in "${!REPOS[@]}"; do
  repo="${REPOS[$i]}"
  repo_num=$((i + 1))
  
  log "==========================================="
  log "Repository $repo_num/${#REPOS[@]}: $repo"
  log "==========================================="
  
  # Check if repository exists
  if [ ! -d "$REPOS_DIR/$repo" ]; then
    log "⚠️  Repository not found, skipping..."
    ((skipped_count++))
    log ""
    continue
  fi
  
  # Skip repos with known incompatibilities (tools not available)
  if [ "$repo" = "mongo-hadoop" ]; then
    log "⚠️  SKIPPING: mongo-hadoop requires network access for Gradle plugin download"
    ((skipped_count++))
    log ""
    continue
  fi
  
  if [ "$repo" = "spring-framework" ] && [ -z "$JAVA24_HOME" ]; then
    log "⚠️  SKIPPING: spring-framework requires JDK 25 (not installed)"
    log "   To fix: Install JDK 25 from https://jdk.java.net/25/"
    ((skipped_count++))
    log ""
    continue
  fi
  
  if [ "$repo" = "ofbiz" ]; then
    log "⚠️  SKIPPING: ofbiz has compile error (OFBizSecurity.java:52 - type inference issue)"
    log "   Requires JDK 7 or code fix. See: framework/security/src/org/ofbiz/security/OFBizSecurity.java:52"
    ((skipped_count++))
    log ""
    continue
  fi
  
  # Set Java version for this repo
  if ! set_java_for_repo "$repo"; then
    log "❌ $repo: FAILED (no suitable JDK)"
    ((failed_count++))
    log ""
    continue
  fi
  
  # Create database
  if create_database "$repo"; then
    # Run queries
    if run_queries "$repo"; then
      generate_metadata "$repo"
      ((success_count++))
      log "✅ $repo: COMPLETE"
    else
      ((failed_count++))
      log "❌ $repo: FAILED (analysis)"
    fi
  else
    ((failed_count++))
    log "❌ $repo: FAILED (database creation)"
  fi
  
  log ""
done

# ============================================================================
# FINAL SUMMARY
# ============================================================================

log "==========================================="
log "FINAL SUMMARY"
log "==========================================="
log "Total repositories: ${#REPOS[@]}"
log "✅ Successful: $success_count"
log "❌ Failed: $failed_count"
log "⚠️  Skipped: $skipped_count"
log ""
log "Results saved to: $RESULTS_DIR"
log "Databases saved to: $DATABASES_DIR"
log ""

# Generate overall summary CSV
log "Generating overall summary..."

export RESULTS_DIR
python3 - <<'PYTHON_SCRIPT'
import json
import csv
import os
from pathlib import Path

results_dir = Path(os.environ.get("RESULTS_DIR", "results/codeql"))
summary_file = results_dir / "codeql_summary.csv"

repos_data = []

for repo_dir in sorted(results_dir.glob("*")):
    if repo_dir.is_dir():
        metadata_file = repo_dir / f"{repo_dir.name}_codeql.metadata.json"
        if metadata_file.exists():
            with open(metadata_file) as f:
                data = json.load(f)
                repos_data.append({
                    'repository': data['repository'],
                    'database_status': data['database_status'],
                    'findings': data['findings_count']
                })

if repos_data:
    with open(summary_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['repository', 'database_status', 'findings'])
        writer.writeheader()
        writer.writerows(repos_data)
    
    print(f"✅ Summary saved to: {summary_file}")
    print(f"   Total findings: {sum(r['findings'] for r in repos_data)}")
else:
    print("⚠️  No results to summarize")
PYTHON_SCRIPT

log ""
log "==========================================="
log "DONE"
log "==========================================="

