#!/bin/bash

# Comprehensive test script for Vulnera
# Runs all test suites with proper configuration and reporting

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COVERAGE_THRESHOLD=${COVERAGE_THRESHOLD:-95}
TEST_TIMEOUT=${TEST_TIMEOUT:-300}
PARALLEL_JOBS=${PARALLEL_JOBS:-4}
ENABLE_COVERAGE=${ENABLE_COVERAGE:-1}
ENABLE_BENCHMARKS=${ENABLE_BENCHMARKS:-0}
ENABLE_PROPERTY_TESTS=${ENABLE_PROPERTY_TESTS:-0}
ENABLE_AUDIT=${ENABLE_AUDIT:-0}
VERBOSE=${VERBOSE:-0}
JUNIT_REPORT=${JUNIT_REPORT:-1}

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
START_TIME=$(date +%s)

# Log function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Function to run a test command with timeout and logging
run_test() {
    local test_name="$1"
    local test_command="$2"
    local test_dir="${3:-$PROJECT_ROOT}"

    log "Running $test_name..."

    if [[ $VERBOSE -eq 1 ]]; then
        log_info "Command: $test_command"
        log_info "Directory: $test_dir"
    fi

    local start_time=$(date +%s)
    local exit_code=0

    cd "$test_dir"

    if timeout ${TEST_TIMEOUT}s bash -c "$test_command" > "test-output-${test_name// /_}.log" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_success "$test_name completed in ${duration}s"
        ((PASSED_TESTS++))
        return 0
    else
        exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        if [[ $exit_code -eq 124 ]]; then
            log_error "$test_name timed out after ${TEST_TIMEOUT}s"
        else
            log_error "$test_name failed (exit code: $exit_code) after ${duration}s"
        fi

        if [[ $VERBOSE -eq 1 ]]; then
            echo -e "${RED}--- Error Output ---${NC}"
            tail -20 "test-output-${test_name// /_}.log" || true
            echo -e "${RED}--- End Error Output ---${NC}"
        fi

        ((FAILED_TESTS++))
        return $exit_code
    fi
}

# Function to check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    local missing_tools=()

    # Check for required tools
    if ! command -v cargo &> /dev/null; then
        missing_tools+=("cargo")
    fi

    if [[ $ENABLE_COVERAGE -eq 1 ]] && ! command -v cargo-tarpaulin &> /dev/null; then
        log_warning "cargo-tarpaulin not found, attempting to install..."
        if ! cargo install cargo-tarpaulin; then
            missing_tools+=("cargo-tarpaulin")
        fi
    fi

    if [[ $ENABLE_AUDIT -eq 1 ]] && ! command -v cargo-audit &> /dev/null; then
        log_warning "cargo-audit not found, attempting to install..."
        if ! cargo install cargo-audit; then
            missing_tools+=("cargo-audit")
        fi
    fi

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi

    log_success "All prerequisites met"
}

# Function to setup test environment
setup_test_environment() {
    log "Setting up test environment..."

    cd "$PROJECT_ROOT"

    # Clean previous test artifacts
    rm -rf coverage/ target/debug/deps/*test* test-output-*.log test-results.xml || true

    # Create necessary directories
    mkdir -p coverage logs

    # Set environment variables
    export RUST_LOG=${RUST_LOG:-warn}
    export RUST_BACKTRACE=${RUST_BACKTRACE:-1}
    export VULNERA__CACHE__DIRECTORY="$(mktemp -d)"
    export VULNERA__SERVER__ENABLE_DOCS=true

    log_success "Test environment setup complete"
}

# Function to run linting checks
run_linting_checks() {
    log "Running linting checks..."
    ((TOTAL_TESTS++))

    local lint_commands=(
        "cargo fmt -- --check"
        "cargo clippy --all-targets --all-features -- -D warnings"
    )

    for cmd in "${lint_commands[@]}"; do
        if ! run_test "Linting: $cmd" "$cmd"; then
            return 1
        fi
    done

    return 0
}

# Function to run unit tests
run_unit_tests() {
    log "Running unit tests..."
    ((TOTAL_TESTS++))

    local unit_test_cmd="cargo test --lib --bins"

    if [[ $PARALLEL_JOBS -gt 1 ]]; then
        unit_test_cmd="$unit_test_cmd -- --test-threads $PARALLEL_JOBS"
    fi

    run_test "Unit Tests" "$unit_test_cmd"
}

# Function to run integration tests
run_integration_tests() {
    log "Running integration tests..."
    ((TOTAL_TESTS++))

    local integration_test_cmd="cargo test --test integration_tests"

    if [[ $PARALLEL_JOBS -eq 1 ]]; then
        integration_test_cmd="$integration_test_cmd -- --test-threads 1"
    fi

    run_test "Integration Tests" "$integration_test_cmd"
}

# Function to run specific test modules
run_module_tests() {
    log "Running module-specific tests..."

    local modules=(
        "parser_edge_cases"
        "api_client_tests"
        "repository_cache_tests"
        "controller_tests"
    )

    for module in "${modules[@]}"; do
        ((TOTAL_TESTS++))
        run_test "Module Tests: $module" "cargo test $module -- --nocapture"
    done
}

# Function to run property-based tests
run_property_tests() {
    if [[ $ENABLE_PROPERTY_TESTS -ne 1 ]]; then
        return 0
    fi

    log "Running property-based tests..."
    ((TOTAL_TESTS++))

    run_test "Property Tests" "cargo test --features property-tests proptest"
}

# Function to run benchmarks
run_benchmarks() {
    if [[ $ENABLE_BENCHMARKS -ne 1 ]]; then
        return 0
    fi

    log "Running benchmarks..."
    ((TOTAL_TESTS++))

    run_test "Benchmarks" "cargo bench --features benchmark"
}

# Function to run security audit
run_security_audit() {
    if [[ $ENABLE_AUDIT -ne 1 ]]; then
        return 0
    fi

    log "Running security audit..."
    ((TOTAL_TESTS++))

    run_test "Security Audit" "cargo audit"
}

# Function to run coverage analysis
run_coverage_analysis() {
    if [[ $ENABLE_COVERAGE -ne 1 ]]; then
        return 0
    fi

    log "Running coverage analysis..."
    ((TOTAL_TESTS++))

    local coverage_cmd="cargo tarpaulin --out Html --output-dir coverage --timeout 600"

    if [[ $VERBOSE -eq 1 ]]; then
        coverage_cmd="$coverage_cmd --verbose"
    fi

    if run_test "Coverage Analysis" "$coverage_cmd"; then
        # Parse coverage percentage
        local coverage_file="coverage/tarpaulin-report.html"
        if [[ -f "$coverage_file" ]]; then
            local coverage_percent=$(grep -o '[0-9]\+\.[0-9]\+% coverage' "$coverage_file" | head -1 | cut -d'%' -f1 || echo "0")
            log_info "Current coverage: ${coverage_percent}%"

            if (( $(echo "$coverage_percent >= $COVERAGE_THRESHOLD" | bc -l) )); then
                log_success "Coverage threshold met (${coverage_percent}% >= ${COVERAGE_THRESHOLD}%)"
            else
                log_error "Coverage threshold not met (${coverage_percent}% < ${COVERAGE_THRESHOLD}%)"
                return 1
            fi
        fi
    fi
}

# Function to run documentation tests
run_doc_tests() {
    log "Running documentation tests..."
    ((TOTAL_TESTS++))

    run_test "Documentation Tests" "cargo test --doc"
}

# Function to generate reports
generate_reports() {
    log "Generating test reports..."

    local end_time=$(date +%s)
    local total_duration=$((end_time - START_TIME))

    # Create summary report
    cat > test-summary.md << EOF
# Vulnera Test Suite Summary

**Execution Date:** $(date)
**Total Duration:** ${total_duration}s
**Total Test Suites:** $TOTAL_TESTS
**Passed:** $PASSED_TESTS
**Failed:** $FAILED_TESTS
**Success Rate:** $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%

## Configuration
- Coverage Threshold: ${COVERAGE_THRESHOLD}%
- Test Timeout: ${TEST_TIMEOUT}s
- Parallel Jobs: ${PARALLEL_JOBS}
- Coverage Enabled: $([ $ENABLE_COVERAGE -eq 1 ] && echo "Yes" || echo "No")
- Benchmarks Enabled: $([ $ENABLE_BENCHMARKS -eq 1 ] && echo "Yes" || echo "No")
- Property Tests Enabled: $([ $ENABLE_PROPERTY_TESTS -eq 1 ] && echo "Yes" || echo "No")
- Security Audit Enabled: $([ $ENABLE_AUDIT -eq 1 ] && echo "Yes" || echo "No")

## Test Logs
EOF

    # Add log file references
    for log_file in test-output-*.log; do
        if [[ -f "$log_file" ]]; then
            echo "- [$log_file](./$log_file)" >> test-summary.md
        fi
    done

    # Generate JUnit XML report if requested
    if [[ $JUNIT_REPORT -eq 1 ]]; then
        generate_junit_xml
    fi

    log_success "Reports generated"
}

# Function to generate JUnit XML report
generate_junit_xml() {
    local junit_file="test-results.xml"

    cat > "$junit_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="$TOTAL_TESTS" failures="$FAILED_TESTS" time="$(($(date +%s) - START_TIME))">
  <testsuite name="VulneraTestSuite" tests="$TOTAL_TESTS" failures="$FAILED_TESTS" time="$(($(date +%s) - START_TIME))">
EOF

    # Add test cases (simplified - in a real implementation, you'd parse individual test results)
    echo "    <testcase name=\"ComprehensiveTestSuite\" time=\"$(($(date +%s) - START_TIME))\">" >> "$junit_file"

    if [[ $FAILED_TESTS -gt 0 ]]; then
        echo "      <failure message=\"$FAILED_TESTS test suites failed\">Test execution failed</failure>" >> "$junit_file"
    fi

    cat >> "$junit_file" << EOF
    </testcase>
  </testsuite>
</testsuites>
EOF

    log_info "JUnit XML report saved to $junit_file"
}

# Function to cleanup
cleanup() {
    log "Cleaning up..."

    # Clean up temporary cache directory
    if [[ -n "${VULNERA__CACHE__DIRECTORY:-}" && -d "$VULNERA__CACHE__DIRECTORY" ]]; then
        rm -rf "$VULNERA__CACHE__DIRECTORY"
    fi

    # Compress log files
    if command -v gzip &> /dev/null; then
        gzip test-output-*.log 2>/dev/null || true
    fi
}

# Function to print final summary
print_summary() {
    echo
    echo "=============================================================================="
    echo -e "${PURPLE}🎯 VULNERA TEST SUITE SUMMARY${NC}"
    echo "=============================================================================="

    local end_time=$(date +%s)
    local total_duration=$((end_time - START_TIME))
    local success_rate=0

    if [[ $TOTAL_TESTS -gt 0 ]]; then
        success_rate=$(( PASSED_TESTS * 100 / TOTAL_TESTS ))
    fi

    echo -e "📊 ${CYAN}Results:${NC} $PASSED_TESTS/$TOTAL_TESTS test suites passed (${success_rate}%)"
    echo -e "⏱️  ${CYAN}Duration:${NC} ${total_duration}s"
    echo -e "🔧 ${CYAN}Configuration:${NC}"
    echo -e "   - Coverage: $([ $ENABLE_COVERAGE -eq 1 ] && echo "✅" || echo "❌") (Threshold: ${COVERAGE_THRESHOLD}%)"
    echo -e "   - Benchmarks: $([ $ENABLE_BENCHMARKS -eq 1 ] && echo "✅" || echo "❌")"
    echo -e "   - Property Tests: $([ $ENABLE_PROPERTY_TESTS -eq 1 ] && echo "✅" || echo "❌")"
    echo -e "   - Security Audit: $([ $ENABLE_AUDIT -eq 1 ] && echo "✅" || echo "❌")"

    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo
        echo -e "${GREEN}🎉 ALL TESTS PASSED! Ready for deployment.${NC}"
        echo -e "${GREEN}✅ Code quality standards met${NC}"
        if [[ $ENABLE_COVERAGE -eq 1 ]]; then
            echo -e "${GREEN}✅ Coverage threshold satisfied${NC}"
        fi
    else
        echo
        echo -e "${RED}💥 $FAILED_TESTS TEST SUITE(S) FAILED${NC}"
        echo -e "${RED}❌ Please fix issues before deployment${NC}"
        echo
        echo -e "${YELLOW}📋 Failed test suites - check logs for details:${NC}"
        ls -la test-output-*.log 2>/dev/null | grep -v ".gz" || echo "No log files found"
    fi

    echo "=============================================================================="

    if [[ $ENABLE_COVERAGE -eq 1 && -f "coverage/tarpaulin-report.html" ]]; then
        echo -e "${CYAN}📊 Coverage report: coverage/tarpaulin-report.html${NC}"
    fi

    if [[ $JUNIT_REPORT -eq 1 && -f "test-results.xml" ]]; then
        echo -e "${CYAN}📄 JUnit report: test-results.xml${NC}"
    fi

    echo -e "${CYAN}📋 Summary report: test-summary.md${NC}"
    echo "=============================================================================="
}

# Function to show help
show_help() {
    cat << EOF
Vulnera Comprehensive Test Suite

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -c, --coverage          Enable coverage analysis
    -b, --benchmarks        Enable benchmark tests
    -p, --property-tests    Enable property-based tests
    -a, --audit             Enable security audit
    --no-coverage          Disable coverage analysis
    --junit                Enable JUnit XML report generation
    --threshold N          Set coverage threshold (default: 95)
    --timeout N            Set test timeout in seconds (default: 300)
    --jobs N               Set number of parallel jobs (default: 4)

ENVIRONMENT VARIABLES:
    COVERAGE_THRESHOLD     Coverage threshold percentage (default: 95)
    TEST_TIMEOUT          Test timeout in seconds (default: 300)
    PARALLEL_JOBS         Number of parallel test jobs (default: 4)
    ENABLE_COVERAGE       Enable coverage analysis (1/0, default: 1)
    ENABLE_BENCHMARKS     Enable benchmarks (1/0, default: 0)
    ENABLE_PROPERTY_TESTS Enable property tests (1/0, default: 0)
    ENABLE_AUDIT          Enable security audit (1/0, default: 0)
    VERBOSE               Enable verbose output (1/0, default: 0)
    JUNIT_REPORT          Generate JUnit XML (1/0, default: 1)

EXAMPLES:
    $0                                    # Run all tests with defaults
    $0 --verbose --coverage               # Run with coverage and verbose output
    $0 --benchmarks --property-tests      # Run with optional test suites
    COVERAGE_THRESHOLD=90 $0 --coverage   # Run with custom coverage threshold

EOF
}

# Main execution function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -c|--coverage)
                ENABLE_COVERAGE=1
                shift
                ;;
            --no-coverage)
                ENABLE_COVERAGE=0
                shift
                ;;
            -b|--benchmarks)
                ENABLE_BENCHMARKS=1
                shift
                ;;
            -p|--property-tests)
                ENABLE_PROPERTY_TESTS=1
                shift
                ;;
            -a|--audit)
                ENABLE_AUDIT=1
                shift
                ;;
            --junit)
                JUNIT_REPORT=1
                shift
                ;;
            --threshold)
                COVERAGE_THRESHOLD="$2"
                shift 2
                ;;
            --timeout)
                TEST_TIMEOUT="$2"
                shift 2
                ;;
            --jobs)
                PARALLEL_JOBS="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Set up signal handlers
    trap cleanup EXIT
    trap 'log_error "Test suite interrupted"; exit 130' INT TERM

    # Print configuration
    echo -e "${PURPLE}🚀 VULNERA COMPREHENSIVE TEST SUITE${NC}"
    echo "=============================================================================="
    log_info "Starting comprehensive test suite"
    log_info "Configuration:"
    log_info "  Coverage: $([ $ENABLE_COVERAGE -eq 1 ] && echo "enabled" || echo "disabled") (threshold: ${COVERAGE_THRESHOLD}%)"
    log_info "  Benchmarks: $([ $ENABLE_BENCHMARKS -eq 1 ] && echo "enabled" || echo "disabled")"
    log_info "  Property Tests: $([ $ENABLE_PROPERTY_TESTS -eq 1 ] && echo "enabled" || echo "disabled")"
    log_info "  Security Audit: $([ $ENABLE_AUDIT -eq 1 ] && echo "enabled" || echo "disabled")"
    log_info "  Verbose: $([ $VERBOSE -eq 1 ] && echo "enabled" || echo "disabled")"
    log_info "  Parallel Jobs: $PARALLEL_JOBS"
    log_info "  Test Timeout: ${TEST_TIMEOUT}s"
    echo "=============================================================================="

    # Execute test pipeline
    check_prerequisites
    setup_test_environment

    # Run test suites in order
    run_linting_checks
    run_unit_tests
    run_module_tests
    run_integration_tests
    run_doc_tests
    run_property_tests
    run_benchmarks
    run_security_audit
    run_coverage_analysis

    # Generate reports and cleanup
    generate_reports
    print_summary

    # Exit with appropriate code
    if [[ $FAILED_TESTS -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
